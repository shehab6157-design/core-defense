#!/usr/bin/env bash
# Install the core-defense arm as a locked-down systemd service (Phase 7a/7b).
# Run on the VM:  sudo bash install_arm.sh
# Options (environment variables):
#   FIREWALL=1      use the REAL nftables backend (default 0 = dry-run)
#   MGMT=IP         management address that is ALWAYS allowed (default 192.168.109.1)
#   DEADMAN=SECS    kernel dead-man timeout for blocks (default 900)
set -euo pipefail

SRC="${SRC:-/home/shehab-shibli/core-defense}"
NAME="${NAME:-arm-01}"
FIREWALL="${FIREWALL:-0}"
MGMT="${MGMT:-192.168.109.1}"
DEADMAN="${DEADMAN:-900}"
HOSTNAME_IN_LOGS="$(hostname)"
OWN_IP="$(hostname -I | awk '{print $1}')"

echo "== 1. service user (no login, no home)"
id coredefense >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin coredefense

echo "== 2. code -> /opt/core-defense (no secrets, no tests, no git)"
command -v rsync >/dev/null || apt-get install -y rsync >/dev/null
install -d -m 0755 /opt/core-defense
rsync -a --delete --exclude .git --exclude .venv --exclude secrets --exclude 'state*' \
      --exclude logs --exclude tests --exclude __pycache__ --exclude .pytest_cache \
      "$SRC"/ /opt/core-defense/
chown -R root:root /opt/core-defense
python3 -m venv /opt/core-defense/.venv
/opt/core-defense/.venv/bin/pip install --quiet -r "$SRC/requirements.txt"

echo "== 3. identity -> /etc/core-defense/secrets (CA key is NEVER copied)"
install -d -m 0755 /etc/core-defense
install -d -m 0700 -o coredefense -g coredefense /etc/core-defense/secrets
for f in ca.crt "$NAME.crt" "$NAME.key"; do
    install -m 0600 -o coredefense -g coredefense "$SRC/secrets/$f" "/etc/core-defense/secrets/$f"
done
if [ ! -f /etc/core-defense/secrets/barrier.salt ]; then
    head -c 32 /dev/urandom > /etc/core-defense/secrets/barrier.salt
    chown coredefense:coredefense /etc/core-defense/secrets/barrier.salt
    chmod 0600 /etc/core-defense/secrets/barrier.salt
fi
if [ -e /etc/core-defense/secrets/ca.key ]; then
    echo "!! CA key found in service secrets - refusing"; exit 1
fi

echo "== 4. config (firewall: $([ "$FIREWALL" = 1 ] && echo REAL || echo dry-run))"
FW_ENABLED=false
[ "$FIREWALL" = 1 ] && FW_ENABLED=true
cat > "/etc/core-defense/$NAME.json" << EOF
{
  "name": "$NAME",
  "host": "$HOSTNAME_IN_LOGS",
  "bind": "127.0.0.1",
  "port": 9101,
  "peers": {},
  "inventory": ["$HOSTNAME_IN_LOGS"],
  "secrets": "/etc/core-defense/secrets",
  "auth_log": "/var/log/auth.log",
  "state_dir": "/var/lib/core-defense",
  "trusted_brains": ["brain-01"],
  "operators": ["op-shehab"],
  "protected_hosts": [],
  "responsible_hosts": ["$HOSTNAME_IN_LOGS"],
  "firewall": {"enabled": $FW_ENABLED, "own_ip": "$OWN_IP", "management": ["$MGMT"], "deadman": $DEADMAN}
}
EOF
chmod 0644 "/etc/core-defense/$NAME.json"

echo "== 5. hardened systemd unit"
if [ "$FIREWALL" = 1 ]; then
    CAPS="CAP_NET_ADMIN"
    FAMILIES="AF_INET AF_UNIX AF_NETLINK"
else
    CAPS=""
    FAMILIES="AF_INET AF_UNIX"
fi
cat > /etc/systemd/system/core-defense-arm.service << EOF
[Unit]
Description=core-defense arm ($NAME)
After=network-online.target

[Service]
Type=simple
User=coredefense
Group=coredefense
SupplementaryGroups=adm
WorkingDirectory=/opt/core-defense
ExecStart=/opt/core-defense/.venv/bin/python -m service.arm --config /etc/core-defense/$NAME.json
Restart=on-failure
RestartSec=5
KillSignal=SIGTERM
StateDirectory=core-defense
StateDirectoryMode=0700
UMask=0077

# --- sandbox ---
NoNewPrivileges=yes
CapabilityBoundingSet=$CAPS
AmbientCapabilities=$CAPS
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=$FAMILIES
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
IPAddressDeny=any
IPAddressAllow=localhost 192.168.109.0/24

[Install]
WantedBy=multi-user.target
EOF

echo "== 6. (re)start"
systemctl daemon-reload
systemctl enable core-defense-arm >/dev/null
systemctl restart core-defense-arm
sleep 3
systemctl --no-pager --lines=5 status core-defense-arm || true
echo "== done"
