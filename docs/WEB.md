# The admin web page

Sign in with your account name and a phone approval, then manage your Thessley keys in a browser. It runs on each computer
(the OPi5, this PC) and manages that computer's keys only. There are no passwords.

## Turn it on

    sudo ./install-web.sh                one time: installs the systemd service (not started)
    sudo thessley-pam web on             starts it, now and at every boot;   web off  stops it
    sudo thessley-pam web status         the address and the certificate's SHA-256 fingerprint

Open the address (for example `https://192.168.1.200:47820/`) from a computer on the same network. The page uses a
certificate of its own, made on first start, so the browser warns once: compare the fingerprint in the warning with the
one `web status` prints before you accept. For a certificate your browsers already trust:
`sudo thessley-pam web cert CERT.pem KEY.pem`.

Settings (all `sudo thessley-pam web ...`): `listen ADDRESS` (default: this computer's LAN address; `0.0.0.0` listens
everywhere, only for networks you trust), `port N` (47820), `session MINUTES` (15 idle, 8 h at most).

## What you can do

- **Sign in.** Type your account name. The page shows a QR code and a text link, like an ssh login: approve it with your
  phone, or with the desktop app (`thessley-passkey respond LINK`, or paste the link). On the phone it reads "Approve admin
  page sign-in".
- **Your keys.** List your phones and apps, rename one, switch one off or on, remove one, or add a new phone or app (a QR
  code and link, then compare the 6-digit codes and press "The codes match").
- **Fresh approval for every change.** Renaming, switching off or on, removing, adding, and every admin setting first ask your
  phone ("Approve a change to your keys", or "Approve adding a device"). A stolen browser session can look but not change.
- **Administrators** (members of `sudo`, `admin` or `wheel`, and root) can pick any account and change the settings: how
  long one approval counts for ssh, phone required for ssh, users adding their own phone, text links in approvals. Their own
  phone approves each change.
- **Activity.** The recent approvals, refusals, passes and enrolments for your account (administrators can see everyone's).

## TPM proof

When the Thessley Passkey desktop app enrols a key that is held in a TPM chip (protection "TPM chip + PIN", and so on), it
also sends a proof, and this computer checks it: the chip's own manufacturer certificate chain (against the roots in
`thessley_pam/tpm_roots/`, Intel and AMD shipped), a challenge only that chip can answer (credential activation), and the
chip's certification that the new key was created inside it and cannot leave it. A key that passes shows "TPM 2.0 proof:
verified, a genuine chip from INTC ADL" under **Details** here, and in `thessley-pam list`; a key that fails shows why.

- **The proof is made at enrolment.** A key enrolled before this was added has none; remove it and enrol the app again.
- **It never blocks an enrolment:** without a proof the key is still added, and the page says so.
- **What it does not cover:** revocation lists are not checked, nor the security of the chip's firmware. A maker whose root
  is not in `tpm_roots/` (Infineon, STMicro, Nuvoton, Microsoft's virtual TPMs ...) is not trusted until you add its root
  certificate there as a `.pem` file.
- It needs the `asn1crypto` library (`sudo apt install python3-asn1crypto`): TPM certificates are not always strict DER.
- Phones get no such line: an Android key's attestation chain is stored and shown, but not checked against Google's root.

## How it is kept safe

- Sign-in needs a signature from a phone already enrolled for the account; an account with no key, or that does not exist,
  gets the same answer, and sign-in requests are limited per address.
- Pages carry a strict content policy (no outside scripts or frames), the session cookie is HttpOnly, Secure and
  SameSite=Strict, and every form carries a one-time token.
- It acts only on the signed-in account (an administrator may pick another), looks everything up from strict patterns, and
  escapes everything it shows.
- It runs as root, because the key lists are root-only. Anyone who can approve for an account can sign in as that account
  on this page, so treat an approver like a key to the account.
- It does not change who may log in over ssh by itself: removing every key of an account that ssh requires a phone for locks
  that account out (the page asks for the approval first, but not twice). Keep an administrator's console or another approver.

## Undo

`sudo thessley-pam web off`, then `sudo ./uninstall-web.sh` (keys and settings stay).
