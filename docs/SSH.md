# ssh: key + phone once, then the key alone for N hours

For members of one group, `ssh` needs the ssh key **and** a phone approval. After an approval, the same user logging
in from the same address needs only the key for the next N hours (4 by default in these notes).

## What a "pass" is

A pass is one entry in `/run/thessley-pam/grants/<user>.json` (root only, on tmpfs, so a reboot ends every pass):

- the PAM **service** (`sshd`): a pass for ssh never works for sudo or the login screen;
- the client's **address** (`PAM_RHOST`): a login from another address asks the phone again;
- the **phone** that approved: if it is removed or switched off, its passes end, and switching it back on does not
  bring them back;
- a **fixed end time**: using a pass does not extend it.

### What it does not protect against

sshd does not tell PAM which ssh key was used, so a pass cannot be tied to the key. Someone who holds a valid key for
that user and connects from the same address during the window gets in without the phone. Behind a shared (NAT)
address that can be more than one machine. Keep the window short, and use `end-pass` when in doubt.

## Why there is a small PAM module for ssh

sshd shows plain PAM text (the QR code) to the client only together with a *question*. So for ssh the phone step is
`pam_thessley_phone.so`, which runs `pam-helper --marker`, shows the QR code with
"Approve on your phone, then press Enter", and then waits for the helper's verdict. (`sudo` and the login screens keep
`pam_exec`, which does not have this problem.) The ssh PAM service is always called `sshd`, whatever the binary is
named, so there is no separate PAM service for a test instance: use `Match` blocks and a group, as below.

## Setup on the server

    sudo apt install qrencode python3-cryptography build-essential libpam0g-dev
    sudo ./install.sh
    sudo ./install-ssh.sh                                  # builds and installs pam_thessley_phone.so

    sudo groupadd thessley-ssh                             # who is affected
    sudo usermod -aG thessley-ssh USER
    sudo thessley-pam enroll --user USER                   # their phone (QR code, scan, type yes)
    sudo thessley-pam grace --service sshd --hours 4       # the pass length
    sudo thessley-pam require --service sshd on            # members with no phone are refused (fail closed)

`/etc/ssh/sshd_config`, at the end of the file (a `Match` block must be last):

    Match Group thessley-ssh
        AuthenticationMethods publickey,keyboard-interactive:pam
        KbdInteractiveAuthentication yes

`/etc/pam.d/sshd`, before `@include common-auth`:

    auth  [success=ignore default=1]  pam_succeed_if.so quiet user ingroup thessley-ssh
    auth  [success=done default=die]  pam_thessley_phone.so

and, before `@include common-session` (optional: it only prints the "approved earlier" note once for shell logins; without it
that note is simply not shown):

    session  optional  pam_thessley_phone.so

When the phone step refuses (no phone enrolled, no answer in time, denied), the module shows the reason as a question
("... Press Enter:") and tells sshd not to retry, so the person sees why and the connection ends with "Too many
authentication failures". Plain PAM text would not do: sshd drops it when a login fails, and the client would only say
"Permission denied (keyboard-interactive)".

Everyone not in the group keeps the old rules: the two PAM lines are skipped for them, and password and
keyboard-interactive logins stay switched off by `sshd_config` as before.

Then, **always** in this order:

    sudo sshd -t                     # refuses to continue if the config is invalid
    sudo systemctl reload ssh        # reload, not restart: open sessions stay

Keep one ssh session open while you try a new login, and keep a backup of both files
(`/etc/ssh/sshd_config.bak-*`, `/etc/pam.d/sshd.bak-*`).

### Exempting an admin machine (scripts and deploys)

Anything unattended (scripts, deploys, cron on another machine) cannot press Enter at a prompt. To keep the key alone
for one user from one address, add this block **above** `Match Group thessley-ssh` (sshd uses the first value it
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

    # 1. on the server: print approval links as text under the QR code (the desktop app cannot scan)
    sudo thessley-pam show-link on

    # 2. on the server: start the enrolment; it prints a thessleypam://enroll?... link and a 6-digit code
    sudo thessley-pam enroll --user ubuntu --link

    # 3. on the PC: paste the link; compare the 6-digit code on both screens
    thessley-passkey enroll 'thessleypam://enroll?...' --protect tpm+pin --label "ubuntu-n100 backup"

    # 4. on the server: both should be listed
    sudo thessley-pam list --user ubuntu

Approving a login with the desktop app instead of the phone: the ssh login prints a `Link: thessleypam://sudo?...`
line (the type says `sudo` for ssh as well). On the PC, with the key protection you chose (PIN, TPM, security key):

    thessley-passkey respond 'thessleypam://sudo?...' --approve

or paste the link into the app's "Paste a link" field, or open it from the terminal (the app registers the
`thessleypam:` scheme). You have 60 seconds. The approval grants the usual pass, tied to the approving device: it stops
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
- Approval requests are answered over HTTPS on the LAN, so the PC has to reach the server on ports 47810-47819 while a
  login waits. A second login while one is waiting uses the next port (47811, ...); this is why the link carries `p=`.
- `show-link` is a setting, not a secret: the link works only for that one request and only with a signature from an
  enrolled approver. Turn it off with `sudo thessley-pam show-link off` if you do not want it in the terminal.
- To drop an approver: `sudo thessley-pam list --user ubuntu`, then `sudo thessley-pam remove --user ubuntu ID` (the pass
  it approved ends with it; the admin window can also switch it off without removing it). Removing the app entry on the PC does not remove it on the server; do both.

## Daily use

    sudo thessley-pam passes                  who holds a pass and for how long (under a minute shows as "0 min")
    sudo thessley-pam end-pass --user NAME    end it now
    sudo thessley-pam grace                   show the setting; --service sshd --hours 0 makes every login ask

Logging in: the key is checked first (a wrong key never reaches the phone), then the QR code appears; scan it with
the app, approve with your fingerprint, press Enter. The next logins from that address within the window go straight
in. A shell login shows "approved earlier, valid for another ..." once; `ssh host command` shows nothing. (sshd shows
PAM text from the auth step again when it opens a shell, so the module leaves the note in `/run/thessley-pam/notes` and
prints it in the session step instead; `sudo journalctl -t thessley-pam` records every "pass used".)

## Scripts and other non-interactive clients

A script (or an AI agent such as Claude) that connects without a terminal behaves like this:

- **Without a valid pass** the connection is refused. With `BatchMode=yes` it is refused at once ("Permission denied
  (keyboard-interactive)"); without it, the client has no way to press Enter, so it waits until the request times out
  (about 2 minutes) and is then refused. Either way, the key alone never gets in.
- **With a valid pass** (someone approved from the same address) a client **without** `BatchMode=yes` gets in, with
  no terminal. A client with `BatchMode=yes` is refused even then, because the ssh client does not do
  keyboard-interactive in batch mode. So unattended scripts that must run from a gated address should use
  `-o BatchMode=no` (and `-o ConnectTimeout=...`), or run from an exempted address (key only).
- A pass belongs to the **address**, not to the person or the session: after one person approves, any process on that
  machine can use the key for the rest of the window. That is the point (key + phone once), and the limit.

Tried with Claude as the client on 2026-10-16: with no pass, Claude's login stopped at "Approve on your phone, then
press Enter"; the human scanned the QR code and approved, Claude pressed Enter, the session opened and its commands
ran; a second login inside the window needed no phone (without `BatchMode=yes`); after `end-pass` the same login was
refused again.

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
| "Address already in use" in the log | All approval ports 47810–47819 are taken: ten logins are waiting at once (each waits up to 60 s). One waiting login uses 47810, the next free port is used for the next |
| `Permission denied (keyboard-interactive)` right after the key | The phone did not answer in time, was denied, or the user has no enrolled phone while `require` is on |
| The phone is not asked although it should be | A valid pass exists (`thessley-pam passes`), or the connection comes from an exempted address |
| The phone is asked every time | `grace` is 0 for `sshd`, or each login comes from a different address |
| `Permission denied (keyboard-interactive)` although a pass exists | The client uses `BatchMode=yes`; use `-o BatchMode=no` |
| Logs | `sudo journalctl -t thessley-pam` and `sudo journalctl -u ssh` |
