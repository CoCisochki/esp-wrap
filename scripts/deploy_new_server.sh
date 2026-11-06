#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-root}"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <SERVER_IP> [SSH_USER]"
    echo "Example: $0 198.51.100.1"
    echo "Example: $0 198.51.100.1 ubuntu"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

SSH_TARGET="${SSH_USER}@${TARGET_IP}"

run_ssh() {
    local cmd="$1"
    ssh -o ConnectTimeout=10 "$SSH_TARGET" "$cmd"
}

run_scp() {
    local src="$1"
    local dst="$2"
    scp -o ConnectTimeout=10 "$src" "${SSH_TARGET}:${dst}"
}

mkdir -p "$ROOT_DIR/bin"

echo "[1/5] Building static Linux binaries (esp-server, esp-client)..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$ROOT_DIR/bin/esp-server" ./cmd/esp-server
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$ROOT_DIR/bin/esp-client" ./cmd/esp-client

echo "[2/5] Checking SSH key connectivity to $SSH_TARGET..."
run_ssh "mkdir -p /tmp/esp-install"

echo "[3/5] Uploading binaries and installer to $SSH_TARGET..."
run_scp "$ROOT_DIR/bin/esp-server" "/tmp/esp-install/"
run_scp "$SCRIPT_DIR/install_server.sh" "/tmp/esp-install/"

echo "[4/5] Executing remote installation on $SSH_TARGET..."
run_ssh "bash /tmp/esp-install/install_server.sh && rm -rf /tmp/esp-install"

OUT_DIR="$ROOT_DIR/generated_clients/$TARGET_IP"
mkdir -p "$OUT_DIR"

echo "[5/5] Fetching generated client configs..."
scp -o ConnectTimeout=10 "${SSH_TARGET}:/opt/esp-wrap/client_user*.json" "$OUT_DIR/"

for u in user1 user2; do
    if [ -f "$OUT_DIR/client_${u}.json" ]; then
        UDIR="$OUT_DIR/$u"
        mkdir -p "$UDIR"
        cp "$ROOT_DIR/bin/esp-client" "$UDIR/"
        cp "$SCRIPT_DIR/run_client.sh" "$UDIR/run.sh"
        chmod +x "$UDIR/run.sh"
        cp "$OUT_DIR/client_${u}.json" "$UDIR/client.json"
        tar -czf "$OUT_DIR/esp-client-${u}.tar.gz" -C "$OUT_DIR" "$u"
    fi
done

echo ""
echo "=========================================================="
echo "Deployment completed successfully for $TARGET_IP!"
echo "Client release packages generated in: $OUT_DIR"
for u in user1 user2; do
    if [ -f "$OUT_DIR/esp-client-${u}.tar.gz" ]; then
        echo " -> $OUT_DIR/esp-client-${u}.tar.gz"
    fi
done
echo "=========================================================="
echo "To connect from Linux client: extract archive and run 'sudo ./run.sh start'"
echo "=========================================================="
