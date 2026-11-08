#!/bin/sh
# Kella agent installer (SPEC §8.1).
#   curl -sSL https://get.<domain>/install.sh | sudo sh -s -- --key <enrollment-key> [--cloud https://api.<domain>]
# TODO(Phase 1): host binaries at $DOWNLOAD_BASE/kella-agent-linux-<arch> and verify the SHA-256 checksum.
set -eu

KEY=""
CLOUD="${KELLA_CLOUD_URL:-https://api.kella.example}"
DOWNLOAD_BASE="${KELLA_DOWNLOAD_BASE:-https://get.kella.example/agent/latest}"

while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="$2"; shift 2 ;;
    --cloud) CLOUD="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Run as root (use sudo)." >&2; exit 1; }
[ -n "$KEY" ] || { echo "Missing --key. Create one in Kella under Servers > Add a server." >&2; exit 1; }
command -v nft >/dev/null 2>&1 || { echo "nftables (nft) is required. Install it with: apt install nftables" >&2; exit 1; }

case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

echo "Downloading kella-agent ($ARCH)..."
curl -fsSL "$DOWNLOAD_BASE/kella-agent-linux-$ARCH" -o /usr/local/bin/kella-agent
chmod 0755 /usr/local/bin/kella-agent

mkdir -p /etc/kella /var/lib/kella
chmod 0700 /etc/kella

if [ ! -f /etc/kella/agent.yaml ]; then
  cat > /etc/kella/agent.yaml <<EOF
cloudUrl: $CLOUD
enrollmentKey: $KEY
tokenPath: /etc/kella/token
statePath: /var/lib/kella
logs:
  auth: /var/log/auth.log
  mail: /var/log/mail.log
actions:
  dryRun: false
  requireSigned: true
  commandPublicKey: ""   # filled in by the cloud during enrollment (Phase 1)
  allowlist: []
EOF
  chmod 0600 /etc/kella/agent.yaml
fi

# Firewall sets used by the block_ip actuator. Separate table so we never touch the admin's rules.
nft -f - <<'EOF'
table inet kella {
  set kella_block  { type ipv4_addr; flags timeout; size 65536; }
  set kella_block6 { type ipv6_addr; flags timeout; size 65536; }
  chain input {
    type filter hook input priority -10; policy accept;
    ip  saddr @kella_block  drop
    ip6 saddr @kella_block6 drop
  }
}
EOF

cp "$(dirname "$0")/kella-agent.service" /etc/systemd/system/kella-agent.service 2>/dev/null || \
  curl -fsSL "$DOWNLOAD_BASE/kella-agent.service" -o /etc/systemd/system/kella-agent.service
systemctl daemon-reload
systemctl enable --now kella-agent

echo "Kella agent installed. This server will appear in your dashboard within a minute."
