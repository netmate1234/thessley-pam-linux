# Ubuntu APT repository

The published APT repository is served by the Orange Pi 5 at
`https://wp-opsec.eagleeye-intelligence.com/wp-content/uploads/thessley-apt/`.
The `thessley-pam-linux-installer` package targets Ubuntu 24.04 LTS on amd64 and
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

The guided setup installs the required shared approval service and asks about
each optional integration separately. Every optional choice defaults to No.
It does not edit `sshd_config`, SSH PAM policy, or OpenVPN server configuration.
To run it directly from the source archive instead:

    sudo ./guided-install.sh

The web admin service remains off unless you choose to enable it. Read the
component guides before using SSH, GNOME, or VPN integration. For SSH, keep the
current session open, arm `ssh-config-rollback.sh`, verify a fresh login, and
cancel the timer only after that login succeeds.

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

    packaging/deb/build-repo.sh 0.1.1 /tmp/thessley-apt-repo SIGNING_KEY_ID

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
