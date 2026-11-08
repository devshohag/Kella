#!/bin/sh
# Shield agent installer (SPEC §8.1).
#   curl -sSL https://get.<domain>/install.sh | sudo sh -s -- --key <enrollment-key> [--cloud https://api.<domain>]
# TODO(Phase 1): host binaries at $DOWNLOAD_BASE/shield-agent-linux-<arch> and verify the SHA-256 checksum.
set -eu

KEY=""
CLOUD="${SHIELD_CLOUD_URL:-https://api.shield.example}"
DOWNLOAD_BASE="${SHIELD_DOWNLOAD_BASE:-https://get.shield.example/agent/latest}"

while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="$2"; shift 2 ;;
    --cloud) CLOUD="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root (use sudo)." >&2; exit 1; }
[ -n "$KEY" ] || { echo "Missing --key. Create one in Shield under Servers > Add a server." >&2; exit 1; }
command -v nft >/dev/null 2>&1 || { echo "nftables (nft) is required. Install it with: apt install nftables" >&2; exit 1; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

echo "Downloading shield-agent ($ARCH)..."
curl -fsSL "$DOWNLOAD_BASE/shield-agent-linux-$ARCH" -o /usr/local/bin/shield-agent
chmod 0755 /usr/local/bin/shield-agent

mkdir -p /etc/shield /var/lib/shield
chmod 0700 /etc/shield

if [ ! -f /etc/shield/agent.yaml ]; then
  cat > /etc/shield/agent.yaml <<EOF
cloudUrl: $CLOUD
enrollmentKey: $KEY
tokenPath: /etc/shield/token
statePath: /var/lib/shield
logs:
  auth: /var/log/auth.log
  mail: /var/log/mail.log
actions:
  dryRun: false
  requireSigned: true
  commandPublicKey: ""   # filled in by the cloud during enrollment (Phase 1)
  allowlist: []
EOF
  chmod 0600 /etc/shield/agent.yaml
fi

# Firewall sets used by the block_ip actuator. Separate table so we never touch the admin's rules.
nft -f - <<'EOF'
table inet shield {
  set shield_block  { type ipv4_addr; flags timeout; size 65536; }
  set shield_block6 { type ipv6_addr; flags timeout; size 65536; }
  chain input {
    type filter hook input priority -10; policy accept;
    ip  saddr @shield_block  drop
    ip6 saddr @shield_block6 drop
  }
}
EOF

cp "$(dirname "$0")/shield-agent.service" /etc/systemd/system/shield-agent.service 2>/dev/null || \
  curl -fsSL "$DOWNLOAD_BASE/shield-agent.service" -o /etc/systemd/system/shield-agent.service
systemctl daemon-reload
systemctl enable --now shield-agent

echo "Shield agent installed. This server will appear in your dashboard within a minute."
