#!/bin/sh
# Install the Hublot agent on a Linux host — the Proxmox node, or any box with a text console.
#
#   sudo ./install.sh <panel-ip> [listen-ip]
#
# <panel-ip>  the machine running the panel; nothing else will be allowed to reach the agent.
# [listen-ip] which address to listen on. Defaults to the address this host uses to reach the
#             panel, which on a hypervisor is the management interface — deliberately not
#             0.0.0.0, because a guest on this same host must not be able to reach an agent that
#             can type at a root console (THREAT-MODEL §5).
#
# Run it from the directory that holds host-agent, hublot-agent.service and the udev rule.
set -eu

PANEL_IP="${1:-}"
if [ -z "$PANEL_IP" ]; then
    echo "usage: $0 <panel-ip> [listen-ip]" >&2
    exit 2
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "this needs root: it creates a user, a unit and a udev rule" >&2
    exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)
BIN="$HERE/host-agent"
# Existence, not the executable bit. The binary is usually built on one machine and carried here
# through a Windows checkout, a zip, or an scp — several of which drop the mode — and `install`
# below sets 0755 regardless. Refusing on a missing bit fails a package that is perfectly fine.
[ -f "$BIN" ] || { echo "no host-agent beside this script" >&2; exit 1; }
case "$(head -c 4 "$BIN" | od -An -tx1 | tr -d ' \n')" in
    7f454c46) ;;
    *) echo "$BIN is not a Linux executable — build it for this machine's architecture" >&2; exit 1 ;;
esac

# Ask the routing table rather than guessing: on a Proxmox node the answer is vmbr0's address,
# which is exactly the interface the panel talks to.
LISTEN_IP="${2:-$(ip -4 route get "$PANEL_IP" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)}"
[ -n "$LISTEN_IP" ] || { echo "could not work out which address to listen on; pass it explicitly" >&2; exit 1; }

echo "→ agent will listen on $LISTEN_IP:7842, reachable only from $PANEL_IP"

# ── the user ────────────────────────────────────────────────────────────────
# No login, no shell, no home. `tty` reads the console devices, `input` writes /dev/uinput.
if ! getent passwd hublot >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin hublot
    echo "→ created user hublot"
fi
usermod -aG tty,input hublot

# ── uinput ──────────────────────────────────────────────────────────────────
install -m 0644 "$HERE/99-hublot-uinput.rules" /etc/udev/rules.d/99-hublot-uinput.rules
echo uinput > /etc/modules-load.d/hublot-uinput.conf
modprobe uinput || true
udevadm control --reload-rules && udevadm trigger --subsystem-match=misc --sysname-match=uinput

# ── the binary and the unit ─────────────────────────────────────────────────
install -m 0755 "$BIN" /usr/local/bin/host-agent
sed -e "s|^Environment=HUBLOT_LISTEN=.*|Environment=HUBLOT_LISTEN=$LISTEN_IP:7842|" \
    -e "s|^IPAddressAllow=.*|IPAddressAllow=localhost $PANEL_IP|" \
    "$HERE/hublot-agent.service" > /etc/systemd/system/hublot-agent.service
chmod 0644 /etc/systemd/system/hublot-agent.service

systemctl daemon-reload
systemctl enable --now hublot-agent.service
sleep 1

if ! systemctl is-active --quiet hublot-agent.service; then
    echo "!! the agent did not start. journalctl -u hublot-agent -n 30" >&2
    exit 1
fi

echo
echo "── pair the panel with this host ──────────────────────────────────────"
# Read the identity as the agent's own user; the token is 0700 and must stay that way.
runuser -u hublot -- env HUBLOT_STATE=/var/lib/hublot /usr/local/bin/host-agent --pairing
echo
echo "Paste those two lines into the panel's pairing form. The token is spent on first use."
echo "Then: systemctl status hublot-agent | journalctl -u hublot-agent -f"
