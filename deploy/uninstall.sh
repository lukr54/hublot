#!/bin/sh
# Undo install.sh. Leaves /var/lib/hublot alone unless you ask, because deleting it throws away the
# agent's identity — every paired panel would have to be paired again.
#
#   sudo ./uninstall.sh [--purge]
set -eu

[ "$(id -u)" -eq 0 ] || { echo "this needs root" >&2; exit 1; }

systemctl disable --now hublot-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/hublot-agent.service
systemctl daemon-reload

rm -f /etc/udev/rules.d/99-hublot-uinput.rules /etc/modules-load.d/hublot-uinput.conf
udevadm control --reload-rules || true

rm -f /usr/local/bin/host-agent

if [ "${1:-}" = "--purge" ]; then
    userdel hublot 2>/dev/null || true
    rm -rf /var/lib/hublot
    echo "→ purged: user, identity and all enrolments are gone"
else
    echo "→ removed. /var/lib/hublot and the hublot user are kept; --purge takes those too"
fi
