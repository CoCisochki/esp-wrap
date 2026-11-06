#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
ROOT_PASS="${2:-${SSH_PASS:-}}"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <SERVER_IP> [ROOT_PASSWORD]"
    echo "Example (SSH Key):      $0 198.51.100.1"
    echo "Example (Password):     $0 198.51.100.1 'SecretPass'"
    echo "Or via env var:         SSH_PASS='SecretPass' $0 198.51.100.1"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

run_ssh() {
    local host="$1"
    local cmd="$2"
    if [ -n "$ROOT_PASS" ]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            echo "Error: sshpass is required when passing password." >&2
            exit 1
        fi
        sshpass -p "$ROOT_PASS" ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$host" "$cmd"
    else
        ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$host" "$cmd"
    fi
}

run_scp() {
    local src="$1"
    local dst="$2"
    if [ -n "$ROOT_PASS" ]; then
        if ! command -v sshpass >/dev/null 2>&1; then
            echo "Error: sshpass is required when passing password." >&2
            exit 1
        fi
        sshpass -p "$ROOT_PASS" scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$src" "$dst"
    else
        scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$src" "$dst"
    fi
}

mkdir -p "$ROOT_DIR/bin"

echo "[1/5] Building static Linux binaries (esp-server, esp-client)..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$ROOT_DIR/bin/esp-server" ./cmd/esp-server
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$ROOT_DIR/bin/esp-client" ./cmd/esp-client

echo "[2/5] Checking SSH connectivity to $TARGET_IP..."
run_ssh "$TARGET_IP" "mkdir -p /tmp/esp-install"

echo "[3/5] Uploading binaries and installer to $TARGET_IP..."
run_scp "$ROOT_DIR/bin/esp-server" "root@$TARGET_IP:/tmp/esp-install/"
run_scp "$SCRIPT_DIR/install_server.sh" "root@$TARGET_IP:/tmp/esp-install/"

echo "[4/5] Executing remote installation on $TARGET_IP..."
run_ssh "$TARGET_IP" "bash /tmp/esp-install/install_server.sh && rm -rf /tmp/esp-install"

OUT_DIR="$ROOT_DIR/generated_clients/$TARGET_IP"
mkdir -p "$OUT_DIR"

echo "[5/5] Fetching generated client configs..."
run_scp "root@$TARGET_IP:/opt/esp-wrap/client_user*.json" "$OUT_DIR/"

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
