/*
 * pam_thessley_authtok.so: after the phone has approved a login, give pam_gnome_keyring the user's login
 * password so it can unlock the login keyring, as it would for a typed password.
 *
 *   auth  requisite                      pam_exec.so ... pam-helper --login     (the phone step; failure stops here)
 *   auth  [success=ok default=ignore]    pam_thessley_authtok.so
 *   auth  optional                       pam_gnome_keyring.so
 *
 * It runs /usr/local/lib/thessley-pam/pam-keyring-helper --keyring USER, reads the password from its stdout
 * and stores it as PAM_AUTHTOK. It never decides whether the login succeeds: every outcome returns PAM_IGNORE,
 * and any problem (no helper, no sealed password, TPM state changed, timeout) just leaves the keyring locked.
 * The password is wiped from this process's memory as soon as PAM has its own copy.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define HELPER "/usr/local/lib/thessley-pam/pam-keyring-helper"
#define MAX_PW 256
#define WAIT_MS 20000

static int safe_username(const char *u)
{
    size_t n = strlen(u);
    if (n == 0 || n > 64)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = u[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok)
            return 0;
    }
    return u[0] != '-';
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags; (void)argc; (void)argv;
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || !safe_username(user))
        return PAM_IGNORE;
    if (geteuid() != 0)
        return PAM_IGNORE;

    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0)
        return PAM_IGNORE;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]);
        return PAM_IGNORE;
    }
    if (pid == 0) {
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) { dup2(devnull, 0); dup2(devnull, 2); }
        dup2(fds[1], 1);
        char *const args[] = { (char *)HELPER, (char *)"--keyring", (char *)user, NULL };
        char *const env[] = { (char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
        execve(HELPER, args, env);
        _exit(127);
    }
    close(fds[1]);

    char buf[MAX_PW + 1];
    size_t len = 0;
    int too_long = 0, timed_out = 0;
    for (;;) {
        struct pollfd p = { .fd = fds[0], .events = POLLIN };
        int r = poll(&p, 1, WAIT_MS);
        if (r == 0) { timed_out = 1; break; }
        if (r < 0) { if (errno == EINTR) continue; break; }
        ssize_t n = read(fds[0], buf + len, MAX_PW - len);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        len += (size_t)n;
        if (len >= MAX_PW) { too_long = 1; break; }
    }
    close(fds[0]);
    if (timed_out || too_long)
        kill(pid, SIGKILL);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;

    int ok = !timed_out && !too_long && WIFEXITED(status) && WEXITSTATUS(status) == 0 && len > 0;
    if (ok) {
        buf[len] = '\0';
        pam_set_item(pamh, PAM_AUTHTOK, buf);
    }
    explicit_bzero(buf, sizeof buf);
    return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_IGNORE;
}
