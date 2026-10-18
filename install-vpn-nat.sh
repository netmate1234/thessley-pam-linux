#!/bin/sh
# Lets VPN clients (10.8.0.0/24 by default) reach the home network through this computer, with a systemd unit that sets three
# firewall rules at boot and removes them when stopped:
#
#   sudo ./install-vpn-nat.sh                  install and start;  --dry-run only prints what it would do
#   VPN_SUBNET=10.9.0.0/24 sudo ./install-vpn-nat.sh        another VPN range
#
# 1. NAT: traffic from the VPN range leaving by the LAN interface is rewritten to this computer's address, so the other machines
#    on the LAN answer it (they do not know the VPN range; their replies would go to the router).
# 2. forwarding: VPN -> LAN is accepted, and LAN -> VPN only for replies to those connections. Nothing else is opened: not Docker's
#    networks, not other interfaces. Docker sets the FORWARD policy to DROP, so the rules go into its DOCKER-USER chain when it has
#    one, else into FORWARD.
# The LAN interface is the one holding the default route. Undo: sudo ./uninstall-vpn-nat.sh
set -eu

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }
command -v iptables >/dev/null || { echo "iptables is not installed." >&2; exit 1; }
SUBNET="${VPN_SUBNET:-10.8.0.0/24}"

helper=/usr/local/lib/thessley-pam/vpn-nat
unit=/etc/systemd/system/thessley-pam-vpn-nat.service

helper_text() {
cat <<'HELPER'
#!/bin/sh
# thessley-pam-vpn-nat: start | stop | show      (installed by install-vpn-nat.sh)
set -eu
SUBNET="${VPN_SUBNET:-__SUBNET__}"
LAN="$(ip -o route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')"
[ -n "$LAN" ] || { echo "no default route: no LAN interface" >&2; exit 1; }
if iptables -w -n -L DOCKER-USER >/dev/null 2>&1; then CHAIN=DOCKER-USER; else CHAIN=FORWARD; fi

rules() {   # table chain spec...   (one line each)
  echo "nat POSTROUTING -s $SUBNET -o $LAN -j MASQUERADE"
  echo "filter $CHAIN -i tun+ -o $LAN -s $SUBNET -j ACCEPT"
  echo "filter $CHAIN -i $LAN -o tun+ -d $SUBNET -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
}
case "${1:-show}" in
  start)
    rules | while read -r table chain spec; do
      # shellcheck disable=SC2086
      iptables -w -t "$table" -C "$chain" $spec 2>/dev/null || iptables -w -t "$table" -I "$chain" 1 $spec
    done
    sysctl -q -w net.ipv4.ip_forward=1 ;;
  stop)
    rules | while read -r table chain spec; do
      # shellcheck disable=SC2086
      while iptables -w -t "$table" -C "$chain" $spec 2>/dev/null; do iptables -w -t "$table" -D "$chain" $spec; done
    done ;;
  show) rules ;;
  *) echo "usage: $0 start|stop|show" >&2; exit 2 ;;
esac
HELPER
}

if [ "$DRY" = 1 ]; then
  echo "would install $helper (VPN range $SUBNET) and $unit; the rules it would set here:"
  helper_text | sed "s#__SUBNET__#$SUBNET#" | sh -s show
  exit 0
fi

mkdir -p "$(dirname "$helper")"
helper_text | sed "s#__SUBNET__#$SUBNET#" > "$helper"
chmod 0755 "$helper"
cat > "$unit" <<UNIT
[Unit]
Description=Thessley VPN: let VPN clients reach the home network (NAT and forwarding rules)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$helper start
ExecStop=$helper stop

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
# keep forwarding on after a reboot even without Docker
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-thessley-vpn.conf
systemctl daemon-reload
systemctl enable --now thessley-pam-vpn-nat >/dev/null
echo "Installed and started thessley-pam-vpn-nat. Rules now:"
"$helper" show
