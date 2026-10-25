# Linux APT release and signing key

The Thessley Linux APT repository is signed with the OpenPGP key whose full
fingerprint is:

`563A40578A64324AC1EB05475B76886E9CDB7C03`

The release workstation stores the private key in this dedicated GnuPG home:

`/home/ubuntu/.local/share/thessley-apt-signing/gnupg`

Keep this private key on the release workstation. Never commit it, copy it to
the Orange Pi 5, or include it in a source archive. The Orange Pi serves only
the generated repository files and public keyring.

Before a release, verify that the local signing identity matches the
fingerprint above:

```sh
gpg --homedir "$HOME/.local/share/thessley-apt-signing/gnupg" \
  --fingerprint 5B76886E9CDB7C03
```

Build a versioned package and signed APT repository by setting `GNUPGHOME` to
the dedicated keyring. For example:

```sh
GNUPGHOME="$HOME/.local/share/thessley-apt-signing/gnupg" \
  packaging/deb/build-repo.sh 0.1.2 /tmp/thessley-apt-repo 5B76886E9CDB7C03
```

Upload the generated repository contents to:

`/var/www/wp-dev/wp-content/uploads/thessley-apt/`

Keep a dated backup of the current repository before replacing files. After
upload, verify `InRelease` with the exported public key and confirm that APT
lists the new package version for both amd64 and arm64. The private key must
not be part of that backup or upload.

The guided installer prints an informational UTC comparison before its own
`apt-get update`; time-zone differences do not affect it, and clock skew only
produces a warning there. The first `apt update` used to install the package
still enforces the signed Release file's date validity. If it refuses a
Release file as not yet valid or expired, synchronize system time and retry;
do not disable APT date or signature checks.
