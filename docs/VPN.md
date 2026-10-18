# OpenVPN with a device approval

A VPN client connects only after **two** things: its personal **client certificate** (first factor) and an **approval on the
account's enrolled device** (second factor, the same signed approval as for ssh and sudo). The client's screen shows a page
with a QR code (or a text link); you scan it with the Thessley Passkey app and approve.

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

- The certificate's **common name must equal the account name** typed as the VPN user name. A certificate for `alice` cannot
  start an approval for `bob`, and a stranger without a valid certificate is stopped by OpenVPN before the script runs, so
  nobody can make your phone ask.
- The account needs at least one enrolled device (`sudo thessley-pam list --user NAME`).
- Any trouble (daemon not running, no answer, a denial) is a refusal.

## Install

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

Settings: `vpn public-host NAME`, `vpn page-port N`, `vpn wait SECONDS` (approval window, default 180), `vpn group GROUP` (who
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

    # the second factor
    script-security 2
    auth-user-pass-verify /usr/local/lib/thessley-pam/vpn-auth via-env
    # no grace time: no auth-gen-token (a client that reconnects must be approved again), and no re-key that would ask again
    reneg-sec 0
    push "reneg-sec 0"

    user nobody
    group nogroup                           # must be the group set with: thessley-pam vpn group GROUP
    keepalive 10 120
    persist-key
    persist-tun
    push "route 192.168.1.0 255.255.255.0"  # the networks the VPN reaches

Make the certificates with easy-rsa (or any CA). One client certificate per device, **named after the account**:

    ./easyrsa gen-req alice nopass && ./easyrsa sign-req client alice

## Client profile (`alice.ovpn`)

    client
    dev tun
    proto udp
    remote vpn.example.org 1194
    remote-cert-tls server        # the client checks the SERVER's certificate (the server file says: client)
    auth-user-pass          # user name: alice (the certificate name); password: anything, it is not checked
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

## Tests and limits

    python3 -I tests/test_vpn.py

The tests cover the daemon, the script (exit codes, the files it writes) and the page. They do not start a real OpenVPN: the
first real connection is the check that your OpenVPN version and client honour the pending authentication.

- Each approval is for one connection. There is no grace time and no pass for the VPN (unlike ssh): every connection, and every
  reconnect after the server dropped it, asks the device again. `thessley-pam grace --service openvpn` refuses to set one.
- The apps show it as "Approve VPN login".
