#!/usr/bin/env bash
set -euo pipefail

CMD="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

usage() {
    echo "ESP-Wrap User Management:"
    echo "  $0 add <USER> <SERVER_IP>   - Add user and build client package"
    echo "  $0 list <SERVER_IP>        - List registered users"
    echo "  $0 del <USER> <SERVER_IP>   - Delete user"
    echo ""
    echo "Examples:"
    echo "  $0 add alice 198.51.100.1"
    echo "  $0 list 198.51.100.1"
    exit 1
}

run_ssh() {
    local host="$1"
    local cmd="$2"
    ssh -o ConnectTimeout=10 "root@$host" "$cmd"
}

run_scp() {
    local src="$1"
    local dst="$2"
    scp -o ConnectTimeout=10 "$src" "$dst"
}

get_ssh_target() {
    local target="$1"
    if ip link show tun-esp0 >/dev/null 2>&1; then
        for i in 1 2 3; do
            if ping -c 1 -W 1 10.99.0.1 >/dev/null 2>&1; then
                echo "10.99.0.1"
                return
            fi
            sleep 1
        done
    fi
    echo "$target"
}

if [ -z "$CMD" ]; then
    usage
fi

case "$CMD" in
    add)
        USER_NAME="${2:-}"
        SERVER_IP="${3:-}"
        if [ -z "$USER_NAME" ] || [ -z "$SERVER_IP" ]; then
            usage
        fi

        SSH_TARGET=$(get_ssh_target "$SERVER_IP")

        echo "[1/4] Adding user '$USER_NAME' on server $SERVER_IP (via $SSH_TARGET)..."
        run_ssh "$SSH_TARGET" "/opt/esp-wrap/esp-server -c /opt/esp-wrap/server.json -add-user $USER_NAME"

        OUT_DIR="$ROOT_DIR/generated_clients/$SERVER_IP"
        UDIR="$OUT_DIR/$USER_NAME"
        mkdir -p "$UDIR"

        echo "[2/4] Downloading user config profile..."
        run_scp "root@$SSH_TARGET:/opt/esp-wrap/client_${USER_NAME}.json" "$OUT_DIR/"

        echo "[3/4] Building client package for $USER_NAME..."
        if [ ! -f "$ROOT_DIR/bin/esp-client" ]; then
            mkdir -p "$ROOT_DIR/bin"
            CGO_ENABLED=0 go build -ldflags="-s -w" -o "$ROOT_DIR/bin/esp-client" ./cmd/esp-client
        fi
        cp "$ROOT_DIR/bin/esp-client" "$UDIR/"
        cp "$SCRIPT_DIR/run_client.sh" "$UDIR/run.sh"
        chmod +x "$UDIR/run.sh"
        cp "$OUT_DIR/client_${USER_NAME}.json" "$UDIR/client.json"
        tar -czf "$OUT_DIR/esp-client-${USER_NAME}.tar.gz" -C "$OUT_DIR" "$USER_NAME"

        echo "[4/4] Done!"
        echo "=========================================================="
        echo "User '$USER_NAME' successfully created!"
        echo "Client package ready to deliver:"
        echo " -> $OUT_DIR/esp-client-${USER_NAME}.tar.gz"
        echo "=========================================================="
        ;;

    list)
        SERVER_IP="${2:-}"
        if [ -z "$SERVER_IP" ]; then
            usage
        fi
        SSH_TARGET=$(get_ssh_target "$SERVER_IP")
        echo "[-] Registered users on $SERVER_IP (via $SSH_TARGET):"
        run_ssh "$SSH_TARGET" "/opt/esp-wrap/esp-server -c /opt/esp-wrap/server.json -list-users"
        ;;

    del)
        USER_NAME="${2:-}"
        SERVER_IP="${3:-}"
        if [ -z "$USER_NAME" ] || [ -z "$SERVER_IP" ]; then
            usage
        fi
        SSH_TARGET=$(get_ssh_target "$SERVER_IP")
        echo "[-] Removing user '$USER_NAME' from $SERVER_IP (via $SSH_TARGET)..."
        run_ssh "$SSH_TARGET" "/opt/esp-wrap/esp-server -c /opt/esp-wrap/server.json -del-user $USER_NAME"
        rm -rf "$ROOT_DIR/generated_clients/$SERVER_IP/$USER_NAME" "$ROOT_DIR/generated_clients/$SERVER_IP/esp-client-${USER_NAME}.tar.gz" 2>/dev/null || true
        echo "[+] User '$USER_NAME' deleted."
        ;;

    *)
        usage
        ;;
esac
