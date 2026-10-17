# OpenVPN with a device approval

A VPN client connects only after **two** things: its personal **client certificate** (first factor) and an **approval on the
account's enrolled device** (second factor, the same signed approval as for ssh and sudo). The client's screen shows a page
with a QR code (or a text link); you scan it with the Thessley Passkey app and approve.

    client --UDP 1194--> OpenVPN (checks the certificate)
                              |  runs vpn-auth (as OpenVPN's user, never root)
                              v
                     thessley-pam-vpn (root daemon) --- asks the device: link/QR, signed answer
                              ^                                  ^
        client opens https://HOST:47830/vpn/ID (QR page)         phone connects to HOST:47810-47819

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

| Port | What | When it listens |
|---|---|---|
| UDP 1194 | OpenVPN | always |
| TCP 47830 | the QR page (HTTPS, its own certificate) | always |
| TCP 47810-47819 | the device's approval | only while an approval is waiting |

The device checks the server's certificate fingerprint, which is in the link, so a man in the middle is detected. The browser
warns once about the QR page's self-signed certificate: the page shows nothing secret (the QR code only helps your own
device approve).

Settings: `vpn public-host NAME`, `vpn page-port N`, `vpn wait SECONDS` (approval window, default 180), `vpn group GROUP` (who
may use the daemon's socket: OpenVPN's group; default `nogroup`).

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
    auth-gen-token 14400                    # no new approval for renegotiation while the connection lives (4 h)
    reneg-sec 3600

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

## Tests and limits

    python3 -I tests/test_vpn.py

The tests cover the daemon, the script (exit codes, the files it writes) and the page. They do not start a real OpenVPN: the
first real connection is the check that your OpenVPN version and client honour the pending authentication.

- Each approval is for one connection. Set `sudo thessley-pam grace --service openvpn --hours 4` and the same account from the
  same address needs no new approval for 4 h.
- The apps will show the request as the service `openvpn`; a wording of its own ("VPN login") is still to be added there.
