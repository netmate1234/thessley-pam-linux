/*
 * pam_thessley_phone.so: the phone approval for services where plain PAM text never reaches the person
 * until PAM asks a question (sshd: keyboard-interactive). Used instead of pam_exec there:
 *
 *   auth  [success=done default=die]  pam_thessley_phone.so
 *
 * It runs /usr/local/lib/thessley-pam/pam-helper --marker, collects what the helper prints (the QR code) up to the
 * line THESSLEY-WAIT, shows it with the question "Approve on your phone, then press Enter", and then waits for the
 * helper to finish. Exit 0 from the helper means approved (or a still valid pass), anything else refuses.
 * If the helper finishes before it printed the wait line (a valid pass, a refusal, no phone), its text is shown as
 * plain information and the exit code decides, with no question asked.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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
#define TOTAL_WAIT_S 100

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

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !safe(user) || geteuid() != 0)
        return PAM_AUTH_ERR;

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
        char *const env[] = { (char *)"PAM_TYPE=auth", e_user, e_service, e_rhost, e_tty,
                              (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        execve(HELPER, args, env);
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
        char prompt[MAX_TEXT + 128];
        snprintf(prompt, sizeof prompt, "%s\nApprove on your phone, then press Enter: ", text);
        char *reply = NULL;
        pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &reply, "%s", prompt);
        if (reply) {
            free(reply);
        }
    } else if (len > 0) {
        pam_info(pamh, "%s", text);
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
    close(fds[0]);
    return (done && WIFEXITED(status) && WEXITSTATUS(status) == 0) ? PAM_SUCCESS : PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
