# Thessley Linux APT repository

The published APT repository is served by the Orange Pi 5 at
`https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-apt/`.
The `thessley-pam-linux-installer` package targets Ubuntu 24.04 and 26.04 LTS and Debian 13 (including Armbian based on Debian 13) on amd64 and
arm64. It installs this source tree at `/opt/thessley-pam-linux`, the
`thessley-pam-install` guided-setup command, and runtime dependencies. Installing
the package does not start services, change firewall rules, or edit login policy.

## Install

Download the public archive keyring and add the repository:

    sudo install -d -m 0755 /etc/apt/keyrings
    curl -fsSL https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-apt/thessley-archive-keyring.gpg \
      | sudo tee /etc/apt/keyrings/thessley-archive-keyring.gpg >/dev/null
    sudo chmod 0644 /etc/apt/keyrings/thessley-archive-keyring.gpg
    echo 'deb [arch=amd64,arm64 signed-by=/etc/apt/keyrings/thessley-archive-keyring.gpg] https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-apt stable main' \
      | sudo tee /etc/apt/sources.list.d/thessley.list

After the repository is configured, install the package and launch the guided setup with one command:

    sudo apt update && sudo apt install thessley-pam-linux-installer && sudo thessley-pam-install

The guided setup installs the required shared approval service, enables the
HTTPS web admin page by default (answer `n` to skip), and asks about other
optional integrations. Those choices default to No. VPN-to-LAN forwarding/NAT
is enabled automatically when a LAN route is selected; enter `none` to skip LAN access.
It does not edit
`sshd_config`, SSH PAM policy, or existing OpenVPN server configuration. It
can optionally create a new isolated OpenVPN server with Thessley QR approval
on Ubuntu 24.04, Ubuntu 26.04, and Debian 13; the setup refuses to overwrite an
existing Thessley VPN configuration or PKI. If setup stops after creating the
CA, rerun it in an interactive terminal: it keeps the root-only CA and resumes
the server and client signing steps. If upgrading an encrypted CA, run
`sudo bash /opt/thessley-pam-linux/migrate-vpn-ca-unencrypted.sh` once; it
prompts for the existing passphrase and retains a root-only encrypted backup.
VPN approval is
enabled before phone enrollment starts, so interrupting that step leaves the
web VPN key controls available while VPN logins remain refused until a phone
is associated with the VPN host.

For GNOME login, the QR approval service runs alongside GDM's password service;
password fallback stays enabled by default. If the Thessley Login admin app is
installed, test QR login first while password fallback is still on, then use
its **QR-only GNOME login** switch to block password login. Only accounts with
an enrolled, working phone can use the QR path in that mode. Keep console or
another administrator access available. `sudo ./uninstall-login.sh` restores
password fallback before removing the QR service. Without the admin app, leave
the default password fallback in place. `install-login.sh` arms a 20-minute
rollback timer (which restarts its countdown after reboot); test the boot-time
greeter QR and approve in Admin or run `sudo thessley-install-rollback approve`.
If it is not approved, the previous GDM login configuration is restored.
The shared approval service arms a 60-minute installation-approval timer after
its health check. Verify the phone approval and web page, then approve in Admin
or run `sudo thessley-install-rollback approve`. If it expires, the previous
core app files and service state are restored; VPN configuration, enrolled
phones, and optional SSH/PAM policy are preserved.
To run it directly from the source archive instead:

    sudo ./guided-install.sh

The HTTPS web admin page is enabled by default (answer `n` to skip). Read the
component guides before using SSH, GNOME, or VPN integration. For SSH login
policy changes, use the separate SSH recovery procedure in `docs/SSH.md`.

## Rollback

Installing the APT package only stages source and dependencies; removing it
does not undo a separately run component installer. Remove the package with:

    sudo apt remove thessley-pam-linux-installer

For service or login integration rollback, use the matching component's
documented uninstall procedure. Preserve `/etc/thessley-pam` if you need the
enrolled public keys later.

## Build and publish

Create a dedicated OpenPGP signing key and keep its private key on the release
machine. Export only the public key as `thessley-archive-keyring.gpg`. Build a
package and signed repository with:

    packaging/deb/build-repo.sh 0.1.16 /tmp/thessley-apt-repo SIGNING_KEY_ID

The repository signing key fingerprint is:
`563A40578A64324AC1EB05475B76886E9CDB7C03`. The release workstation's private
keyring is `/home/ubuntu/.local/share/thessley-apt-signing/gnupg`; its secret key
must remain on that workstation and must never be committed or uploaded to OPI5.
Set `GNUPGHOME` to that directory when building. Only the signed repository
files and exported public keyring go to OPI5. See `docs/RELEASING-LINUX.md` for
the documented release procedure.

Upload the resulting directory contents to the Orange Pi 5 at
`/var/www/wp-dev/wp-content/uploads/thessley-apt/`. Do not upload the private
signing key.
