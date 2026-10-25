# OpenVPN with a device approval

A new VPN session connects only after **two** things: its personal **client certificate** (first factor) and an **approval on
the account's enrolled device** (second factor, the same signed approval as for ssh and sudo). The client's screen shows a
page with a QR code (or a text link); you scan it with the Thessley Passkey app and approve. After approval, OpenVPN issues
a session token that it renews hourly while connected. The token remains valid for up to eight hours after its last renewal,
so a network interruption does not immediately require another phone approval.

    client --UDP 1194--> OpenVPN (checks the certificate)
                              |  runs vpn-auth (as OpenVPN's user, never root)
                              v
                     thessley-pam-vpn (root daemon) --- asks the device: link/QR, signed answer
                              ^                                  ^
        client opens https://HOST:47830/vpn/ID (QR page)         phone sends its answer to the same server, port 47830

The page and the device's answer use **one** permanent HTTPS server (port 47830, a certificate that stays the same). The link
carries that port and the certificate's fingerprint, so the phone still trusts exactly that server. Nothing opens a port for an
approval, so approvals cannot fight over a port, and any number can be open at once.

OpenVPN needs version 2.6 or newer for the page ("pending authentication", method `openurl`); older versions still work, but
the client shows nothing while it waits, so the link has to be taken from elsewhere. Debian 13 ships 2.6.

## What the script insists on

- The certificate's **common name must be the account name** typed as the VPN user name, or `account@device`. A certificate for
  `alice` cannot start an approval for `bob`, and a stranger without a valid certificate is stopped by OpenVPN before the script runs, so
  nobody can make your phone ask.
- The account needs at least one enrolled device (`sudo thessley-pam list --user NAME`).
- Any trouble (daemon not running, no answer, a denial) is a refusal.

## Install

The Linux guided installer can create a **new** OpenVPN server configured for Thessley QR approval. Choose that option from
`sudo ./guided-install.sh` (or `sudo thessley-pam-install` from the APT package). It supports Ubuntu 24.04 and 26.04 LTS, and Debian 13 (including Armbian based on Debian 13),
asks for the public host, approving account, tunnel range, UDP port, and client label. It detects a private connected LAN subnet
from the default-route interface, chooses a tunnel default that does not overlap that subnet, and lets you override either range
or choose `none` for LAN routing. Public cloud-facing subnets are not assumed to be LANs. The LAN range must not overlap the VPN
tunnel. It then creates a root-only CA key, server instance, approval service, and first client profile. The CA private key is
unencrypted on disk so web key creation and revocation can run unattended, matching the OPI5 setup. The key is owned by root,
mode 0600, in a root-only directory; this relies on the server's root account and filesystem protection instead of a CA passphrase.
If you have an older encrypted CA, run `sudo bash /opt/thessley-pam-linux/migrate-vpn-ca-unencrypted.sh` once. It asks for the
current passphrase, verifies the key matches its CA certificate, keeps a root-only backup of the encrypted key, and replaces only
the key file with the same unencrypted key. If a run stops after creating the CA but before installing the server config, rerun
the installer; it preserves and resumes the CA. It refuses
to overwrite an existing Thessley server config or approval service.
The VPN approval and OpenVPN services are enabled before the phone-enrollment prompt. If enrollment is interrupted, VPN approval
stays enabled, and the web page can still create a client key; VPN login itself remains refused until a phone is associated with
this VPN host.
The setup can add only the required UDP and TCP allow rules when UFW is already active; it does not enable UFW or change router
settings. Forward the shown UDP port and TCP 47830 on your router before connecting from outside.

The manual steps below are for an already configured OpenVPN server or when you want to configure each piece yourself.

    sudo ./install-vpn.sh
    sudo thessley-pam vpn public-host vpn.example.org      # the name or address a phone outside your network connects to
    sudo thessley-pam vpn on
    sudo thessley-pam vpn status

Forward these on your router to this computer (nothing else needs to be reachable):

| Port | What |
|---|---|
| UDP 1194 | OpenVPN |
| TCP 47830 | the QR page and the device's approval (HTTPS, its own certificate) |

The device checks the server's certificate fingerprint, which is in the link, so a man in the middle is detected. The browser
warns once about the QR page's self-signed certificate: the page shows nothing secret (the QR code only helps your own
device approve).

Settings: `vpn public-host NAME`, `vpn server-port N` (the OpenVPN UDP port, default 1194), `vpn page-port N`, `vpn wait SECONDS` (approval window, default 180), `vpn group GROUP` (who
may use the daemon's socket: OpenVPN's group; default `nogroup`).

## Enrol your phone or desktop app for the VPN

The apps accept an approval link only for a computer on the local network, because a QR code is untrusted input. A VPN login
comes from the internet, so it carries a **public** host. To let the apps answer it, enrol them for the VPN **once, on the
computer's own network**:

    sudo thessley-pam vpn public-host vpn.example.org
    sudo thessley-pam vpn enroll [ACCOUNT]            # the usual enrolment: a QR code and a code you compare

The enrolment link also carries the public host, and the app stores it with the computer ("This also lets this phone approve VPN
logins ... from vpn.example.org"). From then on the app answers a `vpn` request only if its host is **exactly** that one, a
refusal included. A VPN approval for any other address is never contacted, and an app that was enrolled in the ordinary way
(`thessley-pam enroll`) says how to enrol for the VPN instead. A VPN approval is signed as type `vpn`, so it can never be replayed
as a sudo or ssh approval.

If you change `public-host`, enrol again.

On the admin page (`/keys`) the devices enrolled this way have a table of their own, **VPN devices**, apart from the keys for ssh,
sudo and the screen, with **Add a VPN device** (it needs the public host above) and no passes (a VPN connection always asks). A device enrolled
for the VPN before the server remembered it can be moved there with `sudo thessley-pam vpn mark CREDENTIAL_ID [USER]`
(`vpn unmark` puts it back); `thessley-pam list` shows `[VPN host]` on them.

## OpenVPN server (`/etc/openvpn/server/thessley.conf`)

    port 1194
    proto udp
    dev tun
    topology subnet
    server 10.8.0.0 255.255.255.0          # pick a range that does not clash with your other networks
    ca ca.crt
    cert server.crt
    key server.key
    dh none
    tls-crypt ta.key
    tls-version-min 1.2
    remote-cert-tls client
    verify-client-cert require
    crl-verify /etc/openvpn/easy-rsa-thessley/pki/crl.pem
    management /run/openvpn-server/thessley.mgmt unix
    management-client-user root

    # the second factor
    script-security 2
    auth-user-pass-verify /usr/local/lib/thessley-pam/vpn-auth via-env
    # reconnect token issued only after QR approval succeeds; maximum lifetime 8 hours
    auth-gen-token 28800 3600
    auth-gen-token-secret /etc/openvpn/server/thessley-auth-token.key
    # renew tokens every hour; valid tokens handle re-auth without another QR
    reneg-sec 3600
    push "reneg-sec 3600"

    user nobody
    group nogroup                           # must be the group set with: thessley-pam vpn group GROUP
    keepalive 10 300
    persist-key
    persist-tun
    push "route 192.168.1.0 255.255.255.0"  # the networks the VPN reaches

Make the certificates with easy-rsa (or any CA). **One client certificate per device**, named after the account: `ACCOUNT`, or
`ACCOUNT@DEVICE` for each device (`alice@phone`, `alice@laptop`). Two devices must not share a certificate: OpenVPN lets a certificate
name hold one connection, so the second device to connect drops the first ("connection failure" on it, then it reconnects and drops
the other). The helper makes the certificate and a ready profile:

    sudo ./vpn-new-client.sh alice laptop            # writes alice-laptop.ovpn; log in with the user name alice

Create the token signing key once, before starting OpenVPN, and keep it root-only. Preserve this same key across server
restarts; replacing it invalidates tokens clients already hold.

    sudo /usr/sbin/openvpn --genkey auth-token /etc/openvpn/server/thessley-auth-token.key
    sudo chown root:root /etc/openvpn/server/thessley-auth-token.key
    sudo chmod 600 /etc/openvpn/server/thessley-auth-token.key

The Thessley web page can create profiles and revoke client certificates from **Keys → VPN client profiles**. Each action requires a
fresh phone approval. Revoking a certificate updates the CRL, blocks new connections, and disconnects that certificate's active
session through the root-only local OpenVPN management socket. To enable the controls on a configured host, create the initial CRL
and make the CRL readable by OpenVPN after it drops privileges:

    cd /etc/openvpn/easy-rsa-thessley
    EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    chmod 711 /etc/openvpn/easy-rsa-thessley /etc/openvpn/easy-rsa-thessley/pki
    chmod 644 /etc/openvpn/easy-rsa-thessley/pki/crl.pem

Include the three server directives shown above. The EasyRSA and PKI directories are traversable but not listable by other users;
private CA and client keys stay root-only. `install-web.sh` gives the web service write access to the PKI and keeps the CA key
read-only. OpenVPN reads an updated CRL for new connections; the management socket lets the web app end an existing connection for
the revoked certificate without restarting the VPN server.


## Client profile downloaded from the web GUI (`alice.ovpn`)

    client
    dev tun
    proto udp
    remote vpn.example.org 1194
    remote-cert-tls server        # the client checks the SERVER's certificate (the server file says: client)
    <auth-user-pass>        # web GUI downloads embed these two lines
    alice                   # account name matching the certificate
    thessley-qr-login       # placeholder; the server ignores this password
    </auth-user-pass>
    auth-nocache
    <ca> ... </ca>
    <cert> ... </cert>
    <key> ... </key>
    <tls-crypt> ... </tls-crypt>

In **OpenVPN Connect** (3.x) the page opens in the browser by itself. With the command-line client or NetworkManager the
pending-authentication message is shown in the log or not at all; open the address from the log yourself.

## Reaching the home network through the VPN

A VPN client reaches this computer (`10.8.0.1`) at once. The other machines on your network do not know the VPN range, so their
replies would go to the router and never come back. `install-vpn-nat.sh` fixes that with a systemd unit
(`thessley-pam-vpn-nat`) that sets three firewall rules at boot:

- NAT for the VPN range out of the LAN interface, so the machines on the LAN see the connection as coming from this computer;
- forwarding VPN -> LAN, and LAN -> VPN only for replies to those connections.

Nothing else is opened: not Docker's networks, not other interfaces. Docker sets the forwarding policy to DROP, so the rules go
into its `DOCKER-USER` chain when there is one. `sudo ./install-vpn-nat.sh --dry-run` shows the rules first;
`VPN_SUBNET=...` sets another range; `sudo ./uninstall-vpn-nat.sh` removes everything. This opens your home network to a client
that has a valid certificate **and** an approved device, so keep ssh and the other services on it protected as they are now.
The guided installer enables this forwarding by default whenever a LAN route is configured; answer `n` at its prompt to skip it.

## Tests and limits

    python3 -I tests/test_vpn.py

The tests cover the daemon, the script (exit codes, the files it writes) and the page. They do not start a real OpenVPN: the
first real connection is the check that your OpenVPN version and client honour the pending authentication.

- A successful QR approval can be reused only through OpenVPN's server-signed reconnect token, valid for at most eight hours
  after its last renewal (tokens are renewed hourly while connected). The
  client certificate is still checked on every connection; revoking it blocks reconnects. This token does not create an ssh
  pass or a reusable Thessley approval. After expiry, a new connection needs a fresh QR approval.
- The apps show it as "Approve VPN login".
