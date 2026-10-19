/*
 * pam_thessley_phone.so: the phone approval for services where plain PAM text never reaches the person
 * until PAM asks a question (sshd: keyboard-interactive). Used instead of pam_exec there:
 *
 *   auth  [success=done default=die]  pam_thessley_phone.so
 *
 * It runs /usr/local/lib/thessley-pam/pam-helper --marker, collects what the helper prints (the QR code) up to the
 * line THESSLEY-WAIT, sends it as PAM informational text, and then waits for the helper to finish. OpenSSH sends
 * informational text to keyboard-interactive clients without a response prompt, so approval continues automatically.
 * Exit 0 from the helper means approved (or a still valid pass), anything else refuses.
 * If the helper finishes before it printed the wait line (a valid pass, a refusal, no phone), its text is shown as
 * plain information and the exit code decides, with no question asked.
 *
 * One exception, for a login that was let through on a valid pass: sshd shows PAM text from the auth step and then
 * shows it again when it opens a shell, so the note ("approved earlier, valid for ...") would appear twice. Instead
 * the note is left in a root-only file and printed by the session step (pam_sm_open_session below), which sshd
 * shows once, and only for a shell login. The auth step runs in a forked child of sshd, so the note cannot travel
 * inside the PAM handle; a file named after user and client address carries it.
 *
 *   session  optional  pam_thessley_phone.so
 *
 * A refusal (no phone, no answer in time, denied) is shown as a question ("... Press Enter: "): sshd drops plain
 * PAM text when a login fails, so without a question the person would only see "Permission denied".
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define HELPER "/usr/local/lib/thessley-pam/pam-helper"
#define MARKER "THESSLEY-WAIT"
#define MAX_TEXT 16384
#define TOTAL_WAIT_S 130  /* the helper's approval wait (90 s) plus the time to read its text, with margin */
#define NOTE_DIR "/run/thessley-pam/notes"
#define NOTE_MAX_AGE_S 120
#define SSH_LOGIN_MODE_FILE "/etc/thessley-pam/ssh-login-mode"
#define SSH_POLICY_FAILURE_FILE "/etc/thessley-pam/ssh-policy-failure"

enum { SSH_POLICY_QR_ONLY = 1, SSH_POLICY_KEY_QR = 2, SSH_POLICY_KEY_PASSWORD = 4 };

static int ssh_policy_fails_closed(void)
{
    char value[16] = {0};
    int fd = open(SSH_POLICY_FAILURE_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return 0;  /* Preserve the existing recovery behavior until an administrator opts in. */
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) || st.st_size > 8) {
        close(fd);
        return 0;
    }
    ssize_t n = read(fd, value, sizeof value - 1);
    close(fd);
    return (n == 6 || (n == 7 && value[6] == '\n')) && memcmp(value, "closed", 6) == 0;
}

static int ssh_policy_default(void)
{
    return ssh_policy_fails_closed() ? SSH_POLICY_KEY_QR : SSH_POLICY_KEY_QR | SSH_POLICY_KEY_PASSWORD;
}

/* Missing, malformed, or unsafe settings use the administrator-selected recovery behavior. */
static int ssh_login_policy(void)
{
    char value[32] = {0};
    int fd = open(SSH_LOGIN_MODE_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return ssh_policy_default();
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) || st.st_size > 16) {
        close(fd);
        return ssh_policy_default();
    }
    ssize_t n = read(fd, value, sizeof value - 1);
    close(fd);
    if (n <= 0 || n >= (ssize_t)sizeof value - 1)
        return ssh_policy_default();
    value[n] = '\0';
    if (n > 0 && value[n - 1] == '\n')
        value[n - 1] = '\0';
    if (strcmp(value, "phone") == 0 || strcmp(value, "qk") == 0 || strcmp(value, "K") == 0)
        return SSH_POLICY_KEY_QR;
    if (strcmp(value, "fallback") == 0 || strcmp(value, "qkp") == 0 || strcmp(value, "KP") == 0)
        return SSH_POLICY_KEY_QR | SSH_POLICY_KEY_PASSWORD;
    if (strcmp(value, "password") == 0 || strcmp(value, "kp") == 0 || strcmp(value, "P") == 0)
        return SSH_POLICY_KEY_PASSWORD;
    if (strcmp(value, "qr") == 0 || strcmp(value, "q") == 0 || strcmp(value, "O") == 0)
        return SSH_POLICY_QR_ONLY;
    if (strcmp(value, "qr-password") == 0 || strcmp(value, "qp") == 0 || strcmp(value, "OP") == 0)
        return SSH_POLICY_QR_ONLY | SSH_POLICY_KEY_PASSWORD;
    if (strcmp(value, "OK") == 0)
        return SSH_POLICY_QR_ONLY | SSH_POLICY_KEY_QR;
    if (strcmp(value, "OKP") == 0)
        return SSH_POLICY_QR_ONLY | SSH_POLICY_KEY_QR | SSH_POLICY_KEY_PASSWORD;
    return ssh_policy_default();
}

/* OpenSSH 7.8+ exposes prior successful methods to PAM as SSH_AUTH_INFO_0. */
static int ssh_has_publickey(pam_handle_t *pamh)
{
    const char *info = pam_getenv(pamh, "SSH_AUTH_INFO_0");
    if (!info)
        return 0;
    while (*info) {
        while (*info == '\n' || *info == '\r')
            info++;
        const char *end = strchr(info, '\n');
        size_t len = end ? (size_t)(end - info) : strlen(info);
        if (len >= 9 && memcmp(info, "publickey", 9) == 0 &&
            (len == 9 || info[9] == ' ' || info[9] == '\t'))
            return 1;
        if (!end)
            break;
        info = end + 1;
    }
    return 0;
}

static int safe(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n > 255)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f)
            return 0;
    }
    return 1;
}

static const char *item(pam_handle_t *pamh, int type)
{
    const void *v = NULL;
    if (pam_get_item(pamh, type, &v) != PAM_SUCCESS || v == NULL || !safe((const char *)v))
        return "";
    return (const char *)v;
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}


/* The file that carries the pass note from the auth step to the session step; "" if the names are not plain. */
static int note_path(pam_handle_t *pamh, char *out, size_t n)
{
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !safe(user))
        return 0;
    const char *rhost = item(pamh, PAM_RHOST);
    if (!*rhost)
        rhost = "-";
    for (const char *p = user; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '_' && *p != '-')
            return 0;
    for (const char *p = rhost; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != ':' && *p != '_' && *p != '-')
            return 0;
    int w = snprintf(out, n, NOTE_DIR "/%s@%s", user, rhost);
    return w > 0 && (size_t)w < n;
}

/* Show a refusal reason in a way sshd passes on: as a question, answered with Enter (the answer is ignored). */
static int say_refusal(pam_handle_t *pamh, char *msg)
{
    size_t n = strlen(msg);
    while (n > 0 && (msg[n - 1] == '\n' || msg[n - 1] == '\r' || msg[n - 1] == ' '))
        msg[--n] = '\0';
    if (n == 0)
        return 0;
    char *reply = NULL;
    pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &reply, "%s\nPress Enter: ", msg);
    free(reply);
    return 1;
}

static int write_note(pam_handle_t *pamh, const char *text)
{
    char path[512];
    if (!note_path(pamh, path, sizeof path))
        return 0;
    (void)mkdir("/run/thessley-pam", 0700);
    (void)mkdir(NOTE_DIR, 0700);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return 0;
    size_t len = strlen(text), done = 0;
    while (done < len) {
        ssize_t w = write(fd, text + done, len - done);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            break;
        done += (size_t)w;
    }
    close(fd);
    if (done != len) {
        unlink(path);
        return 0;
    }
    return 1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !safe(user) || geteuid() != 0)
        return PAM_AUTH_ERR;

    int is_sshd = strcmp(item(pamh, PAM_SERVICE), "sshd") == 0;
    int policy = is_sshd ? ssh_login_policy() : SSH_POLICY_QR_ONLY | SSH_POLICY_KEY_QR;
    int has_key = is_sshd && ssh_has_publickey(pamh);
    int qr_only_path = is_sshd && !has_key && (policy & SSH_POLICY_QR_ONLY);
    if (is_sshd && !has_key && !qr_only_path)
        return PAM_MAXTRIES;
    if (is_sshd && has_key && !(policy & SSH_POLICY_KEY_QR)) {
        if (!(policy & SSH_POLICY_KEY_PASSWORD))
            return PAM_MAXTRIES;
        return PAM_AUTH_ERR;  /* Key plus account password; PAM continues to common-auth. */
    }

    char e_user[320], e_service[320], e_rhost[320], e_tty[320];
    snprintf(e_user, sizeof e_user, "PAM_USER=%s", user);
    snprintf(e_service, sizeof e_service, "PAM_SERVICE=%s", item(pamh, PAM_SERVICE));
    snprintf(e_rhost, sizeof e_rhost, "PAM_RHOST=%s", item(pamh, PAM_RHOST));
    snprintf(e_tty, sizeof e_tty, "PAM_TTY=%s", item(pamh, PAM_TTY));

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0)
        return PAM_AUTH_ERR;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]);
        return PAM_AUTH_ERR;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) { dup2(devnull, 0); dup2(devnull, 2); }
        dup2(fds[1], 1);
        char *const args[] = { (char *)HELPER, (char *)"--marker", NULL };
        char *const qr_only_env[] = { (char *)"PAM_TYPE=auth", e_user, e_service, e_rhost, e_tty,
                                      (char *)"PAM_QR_ONLY=1", (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        char *const regular_env[] = { (char *)"PAM_TYPE=auth", e_user, e_service, e_rhost, e_tty,
                                      (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        execve(HELPER, args, qr_only_path ? qr_only_env : regular_env);
        _exit(127);
    }
    close(fds[1]);

    static char text[MAX_TEXT + 1];
    size_t len = 0;
    int marker_seen = 0, eof = 0;
    long deadline = now_ms() + TOTAL_WAIT_S * 1000L;

    /* Phase 1: read the helper's output up to the wait marker (or until it ends). */
    while (!marker_seen && !eof) {
        long left = deadline - now_ms();
        if (left <= 0)
            break;
        struct pollfd p = { .fd = fds[0], .events = POLLIN };
        int r = poll(&p, 1, (int)left);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;
        ssize_t n = read(fds[0], text + len, MAX_TEXT - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) { eof = 1; break; }
        len += (size_t)n;
        text[len] = '\0';
        char *m = strstr(text, MARKER);
        if (m) {
            *m = '\0';
            len = (size_t)(m - text);
            marker_seen = 1;
        }
        if (len >= MAX_TEXT)
            break;
    }
    text[len] = '\0';

    if (marker_seen) {
        /* Send the QR as a keyboard-interactive prompt. This is broadly displayed as terminal text by SSH clients;
         * PAM_TEXT_INFO is automatically continued but some clients escape its UTF-8 QR blocks. */
        char prompt[MAX_TEXT + 128];
        snprintf(prompt, sizeof prompt, "%s\nApprove on your phone, then press Enter: ", text);
        char *reply = NULL;
        pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &reply, "%s", prompt);
        free(reply);
    }

    /* Phase 2: the helper's verdict. */
    int status = 0;
    int done = 0;
    while (!done) {
        long left = deadline - now_ms();
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) { done = 1; break; }
        if (w < 0 && errno != EINTR) break;
        if (left <= 0) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            break;
        }
        struct timespec nap = { 0, 100 * 1000 * 1000 };
        nanosleep(&nap, NULL);
    }
    int ok = done && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!marker_seen && len > 0) {
        /* A pass was used: leave the note for the session step. Anything else (a refusal, no phone): say it now. */
        if (ok) {
            if (!write_note(pamh, text))
                pam_info(pamh, "%s", text);
        } else {
            say_refusal(pamh, text);
        }
    } else if (marker_seen && !ok && done) {
        /* The helper printed its verdict after the wait line ("no answer", "denied"): collect and show it. */
        char after[1024];
        size_t m = 0;
        int fl = fcntl(fds[0], F_GETFL);
        if (fl >= 0)
            fcntl(fds[0], F_SETFL, fl | O_NONBLOCK);
        for (;;) {
            ssize_t r = read(fds[0], after + m, sizeof after - 1 - m);
            if (r < 0 && errno == EINTR)
                continue;
            if (r <= 0)
                break;
            m += (size_t)r;
            if (m >= sizeof after - 1)
                break;
        }
        after[m] = '\0';
        say_refusal(pamh, after);
    }
    close(fds[0]);
    if (ok)
        return PAM_SUCCESS;
    if ((policy & SSH_POLICY_KEY_PASSWORD) && has_key)
        return PAM_AUTH_ERR;  /* Continue to common-auth, which asks for the account password. */
    return PAM_MAXTRIES;  /* Phone-required mode must fail closed, including on helper errors. */
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    char path[512];
    if (!note_path(pamh, path, sizeof path))
        return PAM_SUCCESS;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return PAM_SUCCESS;
    char buf[1024];
    struct stat st;
    ssize_t n = -1;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 && time(NULL) - st.st_mtime <= NOTE_MAX_AGE_S)
        n = read(fd, buf, sizeof buf - 1);
    close(fd);
    unlink(path);  /* shown at most once, stale or not */
    if (n > 0) {
        buf[n] = '\0';
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
            buf[--n] = '\0';
        if (n > 0)
            pam_info(pamh, "%s", buf);
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
