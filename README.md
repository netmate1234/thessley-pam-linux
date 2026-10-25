# thessley-pam-linux

Approve logins to a Linux computer with the Thessley Passkey Android app: `sudo`, the GNOME login and lock screens,
and `ssh`. The phone holds a key in Android Keystore (hardware-backed when the device supports it), protected by the
chosen device authentication; the computer only ever holds the matching public key.

## How it works

1. The computer shows a QR code with a link (`thessleypam://...`): its LAN address and port, the SHA-256 of a fresh
   self-signed TLS certificate, a one-time request id and nonce, the user and the computer.
2. The app connects to that address over HTTPS and trusts **only** the certificate named in the code, so the QR code
   (shown on the computer's own screen) is what authenticates the computer to the phone.
3. After a fingerprint, the app POSTs a signed answer (`approve` or `deny`). The signature (ECDSA P-256) covers the
   request type, id, computer, user, nonce, a timestamp and the action. The computer checks it against the enrolled
   public keys of that user and accepts exactly one answer per request.
4. Nothing is sent through any server of ours; phone and computer talk directly on the local network.

## What is in this repository

| Piece | What it does | Install |
|---|---|---|
| `thessley-pam enroll / list / remove` | Add, list and remove the phones that may approve for a user | `sudo ./install.sh` |
| `pam-helper` | The PAM step (run by `pam_exec`): asks the phone, answers yes or no | `sudo ./install.sh` |
| `sudo` phone step | After the password, `sudo` asks the phone | one line in `/etc/pam.d/sudo`, below |
| GNOME login and lock screens | A QR code under the password box; the password keeps working | `sudo ./install-login.sh` |
| Keyring unlock | A QR login unlocks the GNOME keyring (password sealed in the TPM) | `sudo ./install-keyring.sh`, then `sudo thessley-pam keyring-link` |
| Thessley Login (admin window) | Switches, phones, keyring link in one window | `sudo ./install-admin.sh` |
| ssh with a phone pass | ssh key + phone once, then the key alone for N hours | [docs/SSH.md](docs/SSH.md) |
| Admin web page | sign in with a phone approval, manage your keys, settings and activity in a browser | [docs/WEB.md](docs/WEB.md) |
| OpenVPN server | a new OpenVPN instance with phone QR approval and an eight-hour reconnect token | choose the optional server setup in `sudo ./guided-install.sh` (Ubuntu 24.04 or 26.04) |

Install order: `sudo apt install qrencode python3-cryptography python3-asn1crypto`, then `sudo ./install.sh`, then whatever you want from
the table. The installer validates and stages its Python files before changing the installation, saves the previous code and
systemd service state under `/var/backups/thessley-pam-install-*`, and restores them if service activation or the TCP 47810
health check fails. After a successful install it starts a 60-minute installation-approval timer. Verify phone approvals and
the web page, then approve in Admin or run `sudo thessley-install-rollback approve`; otherwise the previous core app files
and service state are restored. This timer does not undo phone enrollment, VPN configuration, or optional SSH/PAM policy.
It never edits `/etc/pam.d` or SSH policy: the helper runs as root, so it must not live in a directory anyone else can write.
Keep the printed backup path until the installation has been verified.

For an interactive Ubuntu/Debian setup, `sudo ./guided-install.sh` checks the clock diagnostically, updates package lists,
installs dependencies, enables the HTTPS web admin page by default (answer `n` to skip), and asks about optional integrations,
including either a new OpenVPN server or an approval hook for an existing server. Choosing a LAN route for a new VPN enables
forwarding automatically, so there is no second confirmation prompt; enter `none` to skip LAN access. A UTC mismatch or unavailable web-time comparison is a warning,
not an install blocker. APT still verifies signed Release metadata dates and may refuse genuinely stale system time; do not
disable those checks. Phone approvals use a short freshness window, so synchronize the phone and computer clocks.

The installer prints an informational UTC clock comparison when the network is available; a mismatch or unavailable
comparison does not block installation, and the system time zone is irrelevant. Phone approvals use a short freshness
window, so the computer and phone clocks still need to be synchronized. APT validates signed repository metadata dates
before this installer runs; if `apt update` says a Release file is not valid yet or has expired, sync system time with
`sudo timedatectl set-ntp true` and retry. Do not disable APT signature or Release-date validation.

### `sudo`

Add to `/etc/pam.d/sudo`, right after `@include common-auth`:

    auth required pam_exec.so stdout seteuid /usr/local/lib/thessley-pam/pam-helper

A user with no enrolled phone is not affected (so nobody who never opted in is locked out). A user *with* a phone must
approve every sudo. If the account still has a `NOPASSWD` rule in `/etc/sudoers.d`, sudo never asks for anything and
this step never runs; the admin window warns about it.

### GNOME login and lock screens

`install-login.sh` installs a PAM service `gdm-thessley` (the phone *instead of* the password) and a GNOME Shell
extension that draws the QR code under the password field on the login screen and, if you enable it
(`gnome-extensions enable thessley-passkey-login@eagleeye-intelligence.com`), on your lock screen. Whichever finishes
first logs you in, so the password always remains. A user without a phone is refused on this path, never let through.
The QR code is sized to the screen (about 36% of its height, 280 to 480 px).

Escape route if the login screen misbehaves: Ctrl+Alt+F3, log in, then
`cd thessley-pam-linux && sudo ./uninstall-login.sh && sudo systemctl restart gdm3`.

### Keyring unlock

A QR login types no password, so the GNOME keyring would stay locked. `sudo thessley-pam keyring-link` asks for the
login password once, checks it, and seals it in the computer's TPM, bound to PCR 7 (the Secure Boot state). After the
phone approves a login, `pam_thessley_authtok.so` takes it from the sealed copy and gives it to `pam_gnome_keyring`.
Any failure (nothing sealed, Secure Boot state changed, TPM busy) just leaves the keyring locked; the login itself
never depends on it. Run `keyring-link` again after changing your password or after a firmware update that changes
PCR 7 (`keyring-status` tells you). Trade-off: whoever is root on a running, approved system can unseal the password.

### Admin window

`thessley-pam-admin` (menu entry "Thessley Login") shows what is switched on and lets you switch the login-screen QR
code, the lock-screen QR code, the sudo phone step and the keyring unlock on and off, switch each phone off (keeps
its key, stops it approving) or remove it, and link or forget the keyring password. The root work goes through one
helper (`admin-helper`) that acts only for the account that started it; with a `NOPASSWD` sudo rule it uses sudo,
otherwise `pkexec`. Note: a `pam_yubico ... debug` line in `/etc/pam.d/common-auth` makes GNOME's administrator
prompt abort ("Unknown line ... from helper"); remove the word `debug` if `pkexec` prompts never appear.

## Commands

    sudo thessley-pam enroll [--user NAME]          add a phone (QR code, matching 6-digit codes, type yes)
    sudo thessley-pam list   [--user NAME]
    sudo thessley-pam remove CREDENTIAL_ID [--user NAME]
    sudo thessley-pam grace --service S --hours H   ask the phone once per H hours for service S (0 = always)
    sudo thessley-pam require --service S on|off    refuse users who have no phone for service S
    sudo thessley-pam passes                        who holds a phone pass now
    sudo thessley-pam end-pass [--user N] [--service S]
    sudo thessley-pam keyring-link | keyring-forget | keyring-status [--user NAME]

## Tests

    python3 -I tests/test_enroll.py
    python3 -I tests/test_sudo.py
    python3 -I tests/test_grace.py
    python3 -I tests/test_keyring.py          # the TPM tests need a software TPM, see the file
    xvfb-run -a python3 -I tests/test_admin.py

They use a fake phone and temporary directories; no root and no real PAM. Anything that touches `/etc/pam.d` or
`sshd_config` was additionally tried on a throwaway account or a copy first.

## Limits worth knowing

- Phone and computer must be on the same network (the phone connects to the computer's LAN address).
- A phone pass (ssh) is tied to the user, the service and the client's address, **not** to the ssh key: see
  [docs/SSH.md](docs/SSH.md).
- The phone step is only as strong as the phone: a lost phone must be removed here (`thessley-pam remove`) and in the app.
- The Linux APT signing key and release procedure are documented in [docs/RELEASING-LINUX.md](docs/RELEASING-LINUX.md).
