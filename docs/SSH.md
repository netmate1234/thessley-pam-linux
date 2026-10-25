# ssh: key + phone once, then the key alone for N hours

For members of one group, `ssh` needs the ssh key **and** a phone approval. After an approval, the same user logging
in from the same address needs only the key for the next N hours (4 by default in these notes).

The default **Allowed source networks for Thessley SSH logins** is detected local networks plus detected VPN
networks. Administrators can change this in `/admin` to all IPs, selected source types, and/or a chosen list of
comma-separated IP addresses/CIDR ranges. All IPs is exclusive. Local and VPN ranges are discovered from active
network interfaces; on a computer that does not host the VPN, add its client subnet to Chosen list. A source outside the selected networks is refused before phone
approval. The four-hour pass is tied to its original client IP by default. Accounts outside `thessley-ssh` are not
covered by this source policy; block those accounts in the per-user SSH controls if needed.

## What a "pass" is

A pass is one entry in `/run/thessley-pam/grants/<user>.json` (root only, on tmpfs, so a reboot ends every pass):

- the PAM **service** (`sshd`): a pass for ssh never works for sudo or the login screen;
- the client's **address** (`PAM_RHOST`), unless the host is configured to let SSH passes apply from any address;
- the **phone** that approved: if it is removed or switched off, its passes end, and switching it back on does not
  bring them back;
- a **fixed end time**: using a pass does not extend it.

### What it does not protect against

sshd does not tell PAM which ssh key was used, so a pass cannot be tied to the key. Someone who holds a valid key for
that user and connects during the window gets in without the phone. In same-IP mode this is limited to that address;
`any` mode allows it from every address. Behind a shared (NAT) address, even same-IP mode can cover more than one
machine. Keep the window short, and use `end-pass` when in doubt.

## Why there is a small PAM module for ssh

For SSH, `pam_thessley_phone.so` runs `pam-helper --marker` and sends the QR as a PAM informational message. SSH
keyboard-interactive displays that message without asking for a reply; the PAM worker waits for the phone approval and
then SSH continues automatically. (`sudo` and the login screens keep `pam_exec`.) The SSH PAM service is always called
`sshd`, whatever the binary is named, so there is no separate PAM service for a test instance: use `Match` blocks and a
group, as below.

## Setup on the server

    sudo apt install qrencode python3-cryptography build-essential libpam0g-dev
    sudo ./install.sh                                      # installs and starts the shared approval listener on TCP 47810
    sudo ./install-ssh.sh                                  # builds and installs pam_thessley_phone.so

    sudo groupadd thessley-ssh                             # who is affected
    sudo usermod -aG thessley-ssh USER
    sudo thessley-pam enroll --user USER                   # their phone (QR code, scan, type yes)
    sudo thessley-pam grace --service sshd --hours 4       # the pass length, same client IP by default
    sudo thessley-pam grace --service sshd --hours 4 --ip-scope any  # optional cloud-host mode
    sudo thessley-pam require --service sshd on            # members with no phone are refused (fail closed)

`/etc/ssh/sshd_config`, at the end of the file (a `Match` block must be last):

    Match Group thessley-ssh
        AuthenticationMethods publickey,keyboard-interactive:pam keyboard-interactive:pam
        KbdInteractiveAuthentication yes

`/etc/pam.d/sshd`, before `@include common-auth`:

    auth  [success=ignore default=1]  pam_succeed_if.so quiet user ingroup thessley-ssh
    auth  [success=done auth_err=ignore default=die]  pam_thessley_phone.so

and, before `@include common-session` (optional: it only prints the "approved earlier" note once for shell logins; without it
that note is simply not shown):

    session  optional  pam_thessley_phone.so

When the phone step refuses (no phone enrolled, no answer in time, denied), the module shows the reason as a question
("... Press Enter:") and tells sshd not to retry, so the person sees why and the connection ends with "Too many
authentication failures". Plain PAM text would not do: sshd drops it when a login fails, and the client would only say
"Permission denied (keyboard-interactive)".

The admin web page has three independent login paths for members of `thessley-ssh`:

- **QR-only:** no SSH key or account password; a fresh phone approval creates the configured SSH pass. Until it expires,
  eligible logins from the configured IP scope can use that pass without another approval. Set the SSH pass to 0 to ask
  for a new phone approval at every login.
- **SSH key + QR approval:** a public key is required, followed by phone approval. A saved SSH pass may apply.
- **SSH key + account password:** a public key and the account password are required. If this and key + QR are both
  enabled, missing phone enrollment, a denied approval, or a timeout can fall back to the account password.

Select any combination, with at least one path enabled. For QR-only or key + password, select those two checkboxes and
leave key + QR unchecked. The settings page and its POST action are restricted to administrators. Changes take effect
on the next login. Keep `AuthenticationMethods` set to both alternatives shown above; the PAM module checks OpenSSH's
`SSH_AUTH_INFO_0` to enforce key requirements. That value is provided to PAM by OpenSSH 7.8 and newer; if it is
missing, key-required policies fail closed. With no valid policy file, the default enables key + QR and key + password
recovery. QR-only remains an explicit opt-in.

### Per-user SSH controls

Administrators can override the computer-wide policy for each account in `thessley-ssh` from **Admin → Users**. These accounts
have checkboxes for QR-only, key + QR, and key + account-password paths, plus **Block SSH**. Leave **Use the computer-wide
policy** checked to inherit the global choices. Multiple path boxes enable alternatives (OR); key + QR together with key +
password gives password recovery when phone approval is unavailable. Accounts outside `thessley-ssh` have a block-only control.
**Block SSH** denies new SSH connections for that account at the SSH server, regardless of authentication method; an existing
session stays connected. Every change requires a fresh approval from the administrator's phone. Per-user login paths are stored
root-only under `/etc/thessley-pam/ssh-users/`; the previous value is kept as a `.bak` file. SSH blocks are stored in the
root-owned `/etc/ssh/sshd_config.d/90-thessley-deny-users.conf`, validated with `sshd -t`, and applied with a reload that keeps
existing sessions open. A missing or invalid login-path override uses the global policy.

The Users section also shows each account's active phone count and links to device management, including first enrollment for
accounts with no phone yet. QR login-path controls apply to `thessley-ssh` members only. The SSH server block applies to any
account and takes precedence over other authentication methods and `Match User` authentication exceptions.

If the computer-wide policy file is missing or unreadable, the default enables key + QR and key + password recovery.

Everyone not in the group keeps the old rules: the two PAM lines are skipped for them, and password and
keyboard-interactive logins stay switched off by `sshd_config` as before.

Use `--ip-scope any` only on hosts where SSH clients can arrive from changing addresses. A pass then applies to that
user and service from every source IP until it expires; it still requires an enrolled phone approval and does not apply
to other PAM services. Switch back with `--ip-scope same`. The setting is stored on this computer.

Before changing SSH or PAM settings, arm the persistent SSH login-recovery timer from this source directory:

    sudo ./ssh-config-rollback.sh arm 10
    sudo ./ssh-config-rollback.sh status

The timer snapshots `/etc/ssh/sshd_config`, the complete `/etc/ssh/sshd_config.d/` directory, and
`/etc/pam.d/sshd`. It is scheduled for the displayed local deadline, runs as root, and survives a reboot. If it is
not cancelled, it restores those files, validates them with `sshd -t`, and reloads the SSH service. Keep your current
SSH session open while testing. If the timer reports no future run time, do not edit the login configuration.

Then, **always** in this order:

    sudo sshd -t                     # refuses to continue if the config is invalid
    sudo systemctl reload ssh        # reload, not restart: open sessions stay

Keep the current SSH session open while you try a fresh login. After the new login succeeds, cancel the timer:

    sudo /usr/local/sbin/thessley-ssh-config-rollback cancel

This timer restores SSH/PAM login configuration only. It does not undo the Thessley app installation, phone-key changes, or VPN configuration. The snapshot remains in `/var/backups/thessley-ssh-config-rollback-*`. Check a pending timer with
`sudo /usr/local/sbin/thessley-ssh-config-rollback status`. If it fires, the old SSH and PAM config is restored
automatically; check `journalctl -u thessley-ssh-config-rollback.service` for its result.

### Exempting an admin machine (scripts and deploys)

Anything unattended (scripts, deploys, cron on another machine) has no person available to approve a phone request. To keep
the key alone for one user from one address, add this block **above** `Match Group thessley-ssh` (sshd uses the first value it
finds, so the order matters):

    Match User ubuntu Address 192.168.1.111
        AuthenticationMethods publickey

and put the user in the group. From that address the user logs in with the key as before; from every other address
the key plus the phone is needed. Give that machine a fixed address on the router, otherwise the exemption silently
stops applying when its address changes (the user can still log in with the phone).

Check what applies to whom without connecting:

    sudo sshd -T -C user=ubuntu,host=x,addr=192.168.1.111 | grep -E '^(authenticationmethods|kbdinteractiveauthentication)'
    sudo sshd -T -C user=ubuntu,host=x,addr=192.168.1.112 | grep -E '^(authenticationmethods|kbdinteractiveauthentication)'

## Reference: the OPi5 (set up 2026-10-16)

`sshtest` and `ubuntu` are in `thessley-ssh`, `grace` is 4 h and `require` is on for `sshd`. **No address is exempted**:
`ubuntu` needs the key and a phone approval from this PC too (an exemption was tried first, then removed on request).
Consequences accepted there: every deploy or script needs an approved pass (one approval covers 4 hours from this
address); when it runs out, unattended connections wait about 2 minutes and fail until someone approves a new
request; clients must not use `BatchMode=yes`. `ajoub` is outside the group and logs in as before. Backups of
`sshd_config` from before each change are `/etc/ssh/sshd_config.bak-thessley*`; to bring the exemption back, re-add
the `Match User ubuntu Address ...` block above.

## A second approver, so a lost phone does not lock you out

`require` refuses a group member with no enrolled phone, and a user normally has one phone. If it is lost, broken or
switched off, `ubuntu` cannot get in over ssh any more. Enrol a second approver while the phone still works. The
Thessley Passkey desktop app (`thessley-passkey-linux`, GTK on Ubuntu, Qt on Windows) speaks the same protocol as the
phone app and counts as one more approver for the same user. Any number can be enrolled; any one of them approves.

Enrol the desktop app (do this from a login that already works; the server must be reachable from the PC over the LAN):

    # 1. on the server: start the enrolment; it prints "Link: thessleypam://enroll?..." above the QR code, and a 6-digit
    #    code (links are printed by default; "sudo thessley-pam show-link off" would hide the ones in approvals)
    sudo thessley-pam enroll --user ubuntu

    # 2. on the PC: paste the link; compare the 6-digit code on both screens
    thessley-passkey enroll 'thessleypam://enroll?...' --protect tpm+pin --label "ubuntu-n100 backup"

    # 3. on the server: both should be listed
    sudo thessley-pam list --user ubuntu

Approving a login with the desktop app instead of the phone: the ssh login prints a `Link: thessleypam://sudo?...`
line (the type says `sudo` for ssh as well). On the PC, with the key protection you chose (PIN, TPM, security key):

    thessley-passkey respond 'thessleypam://sudo?...' --approve

or paste the link into the app's "Paste a link" field, or open it from the terminal (the app registers the
`thessleypam:` scheme). You have 90 seconds. The approval grants the usual pass, tied to the approving device: it stops
working if that device is removed or switched off on the server.

Checked on 2026-10-16: with the pass ended and `ubuntu` logging in from 192.168.1.111, the desktop app approved
(`approved by 'ubuntu-n100' ... for ubuntu (sshd, ssh)` in the log), the session opened, and the next login rode the pass.
The phone was not involved.

Things to know:

- The desktop app keeps its key in the TPM, a PIN, a security key or any mix; whoever can use that can approve. Treat
  the PC like the phone: screen lock, disk encryption, and do not enrol a machine you would not hand the phone to.
- The approver and the ssh client are often the same PC. If that PC and the phone are lost together, no approver is
  left. Enrol a second computer, or keep a break-glass path: console access, or an account outside `thessley-ssh`
  that you only use to repair this.
- Approval requests are answered over HTTPS on the LAN through the shared listener on TCP port 47810. Each pending login
  has its own temporary route and waits in its own PAM helper; another login or phone request can use the same listener at once.
  The link carries the route ID and the listener's certificate fingerprint; it still carries `p=47810` for the app.
  Allow inbound TCP 47810 from the phone's network (LAN or VPN); forward that one port on the router only when the phone must
  reach the computer from outside.
  OpenVPN approvals remain on their separate HTTPS listener on TCP port 47830.
- The text link is printed by default (`Link: thessleypam://...`, above the QR code), for enrolment and for every
  approval, so a phone or computer that cannot scan the screen can still approve. It is not a secret: it works only for
  that one request and only with a signature from an enrolled approver. `sudo thessley-pam show-link off` hides it in
  approvals (enrolment always prints it).
- To drop an approver: `sudo thessley-pam list --user ubuntu`, then `sudo thessley-pam remove --user ubuntu ID` (the pass
  it approved ends with it; the admin window can also switch it off without removing it). Removing the app entry on the PC does not remove it on the server; do both.

## A user adds their own phone (no administrator)

An administrator adds phones with `sudo thessley-pam enroll --user NAME`. A normal user, who has no sudo rights, can add
their **own phones** instead, the way the Windows version allows it (the first one freely, more with approval):

    sudo ./install-selfenroll.sh            once, as an administrator: one file in /etc/sudoers.d
    sudo thessley-pam enroll-me             then, as that user, in a terminal (add --link for the desktop app)

It shows the same QR code and 6-digit code, and the user types `yes`. How it stays safe:

- **The account is not chosen by the user.** The command takes it from sudo (`SUDO_USER`) and has no `--user` option, so
  nobody can add a phone for someone else. The sudoers line allows exactly `enroll-me` and `enroll-me --link`, nothing else.
- **The first phone** needs no approval (there is nobody to ask). **Any further phone** needs a fresh approval from a phone
  already enrolled for that account: `enroll-me` shows the usual QR/link, and the phone's screen says "Approve adding a
  device?". No pass ever counts for this, and a stolen password alone cannot add a phone. If all the account's phones are
  switched off (a lost phone), only an administrator can add one (`sudo thessley-pam enroll --user NAME`).
- **Trade-off:** until a phone is enrolled, whoever can run a session as that account (it takes its password) can enrol
  their own phone first. If you do not want that, turn it off and let only administrators add phones:

      sudo thessley-pam self-enroll off          (on again: self-enroll on; no argument shows the setting)

- Undo the sudoers file with `sudo ./uninstall-selfenroll.sh`.

## Daily use

    sudo thessley-pam passes                  who holds a pass and for how long (under a minute shows as "0 min")
    sudo thessley-pam end-pass --user NAME    end it now
    sudo thessley-pam grace                   show the setting; --service sshd --hours 0 makes every login ask

Logging in: the key is checked first (a wrong key never reaches the phone), then the QR code appears; scan it with
the app and approve with your fingerprint. SSH continues automatically. In same-IP mode, the next logins from that address within the
window go straight in; with `--ip-scope any`, they can come from any address. A shell login shows "approved earlier, valid for another ..." once; `ssh host command` shows nothing. (sshd shows
PAM text from the auth step again when it opens a shell, so the module leaves the note in `/run/thessley-pam/notes` and
prints it in the session step instead. Pass reuse is not written to the journal; explicit approvals and pass grants remain logged.

## Scripts and other non-interactive clients

A script (or an AI agent such as Claude) that connects without a terminal behaves like this:

- **Without a valid pass** the connection waits for the phone. With `BatchMode=yes` it is refused at once ("Permission denied
  (keyboard-interactive)"); otherwise the phone can approve it and SSH continues without terminal input. With no phone answer,
  the request times out and is refused. The key alone never gets in.
- **With a valid pass** (someone approved from the configured address scope) a client **without** `BatchMode=yes` gets in, with
  no terminal. A client with `BatchMode=yes` is refused even then, because the ssh client does not do
  keyboard-interactive in batch mode. So unattended scripts that must run from a gated address should use
  `-o BatchMode=no` (and `-o ConnectTimeout=...`), or run from an exempted address (key only).
- A pass belongs to the **configured address scope**, not to the person or the session: after one person approves, any
  process with that user's key can use it during the window. That is the point (key + phone once), and the limit.

The shared listener serves all pending approvals on port 47810. A phone response is routed by its random challenge path,
verified by the corresponding PAM helper, and removed when that approval finishes or times out. The listener does not wait
for a phone response inside an HTTP request, so one pending login does not hold the port or block other logins.

## Testing without a second computer

A second address on the same network card makes the server see "another place":

    sudo ip addr add 192.168.1.112/24 dev enp1s0          # pick a free address
    ssh -b 192.168.1.112 server                            # from the admin machine
    sudo ip addr del 192.168.1.112/24 dev enp1s0          # remove it again

To watch a pass expire, set `--hours 0.05` (3 minutes), log in, wait, log in again, then set the real value back.
`tests/test_grace.py` covers the pass logic against a fake phone; the whole chain (real sshd, real PAM, a fake phone)
was run on a throwaway user before any real account was added.

## Undo

- one user: `sudo gpasswd -d USER thessley-ssh`
- everything: remove the `Match Group thessley-ssh` block (and any exemption block) from `sshd_config`, remove the two
  lines from `/etc/pam.d/sshd` (or restore the `.bak-*` copies), `sudo sshd -t && sudo systemctl reload ssh`
- passes: `sudo thessley-pam grace --service sshd --hours 0` (also ends them)

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| The login hangs or shows a `Password:` prompt | The PAM lines are not in `/etc/pam.d/sshd`, or the user is not in the group, or the module is not installed (`install-ssh.sh`) |
| No QR code, no text | The ssh PAM step is `pam_exec` instead of `pam_thessley_phone.so` (sshd holds plain text back) |
| "could not start" in the log | Check `systemctl status thessley-pam-approvals` and `journalctl -u thessley-pam-approvals`; the shared listener must be active on port 47810 |
| `Permission denied (keyboard-interactive)` right after the key | The phone did not answer in time, was denied, or the user has no enrolled phone while `require` is on |
| The phone is not asked although it should be | A valid pass exists (`thessley-pam passes`), or the connection comes from an exempted address |
| The phone is asked every time | `grace` is 0 for `sshd`, or each login comes from a different address |
| `Permission denied (keyboard-interactive)` although a pass exists | The client uses `BatchMode=yes`; use `-o BatchMode=no` |
| “Device clock is off by more than a minute” | Synchronize the phone and Linux system clocks. Their time zones may differ; freshness validation compares UTC timestamps. |
| Logs | `sudo journalctl -t thessley-pam` and `sudo journalctl -u ssh` |
