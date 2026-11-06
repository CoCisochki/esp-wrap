#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    exec sudo bash "$0" "$@"
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$DIR/esp-client"
if [ ! -f "$BIN" ] && [ -f "$DIR/../bin/esp-client" ]; then
    BIN="$DIR/../bin/esp-client"
fi
CONFIG="$DIR/client.json"
if [ ! -f "$CONFIG" ] && [ -f "$DIR/../configs/client.json" ]; then
    CONFIG="$DIR/../configs/client.json"
fi

PIDFILE="/tmp/esp-client.pid"
LOGFILE="/tmp/esp-client.log"

start() {
    stop 2>/dev/null || true
    rm -f "$LOGFILE" 2>/dev/null || true

    if [ ! -f "$BIN" ]; then
        echo "Error: esp-client binary not found at $BIN"
        exit 1
    fi
    if [ ! -f "$CONFIG" ]; then
        echo "Error: client.json configuration not found at $CONFIG"
        exit 1
    fi

    echo "[+] Starting esp-client..."
    setsid "$BIN" -c "$CONFIG" > "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 2

    if ! pgrep -f "$BIN" >/dev/null; then
        echo "[!] Failed to start esp-client. Recent log output:"
        cat "$LOGFILE"
        exit 1
    fi

    echo "[+] esp-client running with PID $(cat "$PIDFILE")"
    echo "[-] Checking tunnel connectivity (10.99.0.1)..."
    if ping -c 2 -W 2 10.99.0.1 >/dev/null 2>&1; then
        echo "[+] Ping to server: OK"
    else
        echo "[?] Server ping not yet acknowledged. Check 'sudo $0 status'."
    fi

    echo "[-] Testing SOCKS5 proxy (127.0.0.1:10951)..."
    PUB_IP=$(curl -s --max-time 5 --socks5-hostname 127.0.0.1:10951 https://api.ipify.org 2>/dev/null || echo "Pending...")
    echo "[+] Public IP via SOCKS5: $PUB_IP"
}

stop() {
    echo "[*] Stopping esp-client..."
    killall -9 esp-client 2>/dev/null || true
    if [ -f "$PIDFILE" ]; then
        kill -9 "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE"
    fi
    ip link del tun-esp0 2>/dev/null || true
    echo "[+] Stopped."
}

status() {
    if pgrep -f "esp-client" >/dev/null; then
        echo "[+] esp-client is running (PID: $(pgrep -f "esp-client" | head -n1))"
        ip -brief addr show dev tun-esp0 2>/dev/null || true
        echo "[-] SOCKS5 port:"
        ss -tulpn | grep 10951 || true
        echo "[-] Public IP via SOCKS5:"
        curl -s --max-time 5 --socks5-hostname 127.0.0.1:10951 https://api.ipify.org || echo "FAIL"
    else
        echo "[-] esp-client is not running."
    fi
}

case "${1:-start}" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; sleep 1; start ;;
    status)  status ;;
    log)     tail -f "$LOGFILE" ;;
    *) echo "Usage: $0 {start|stop|restart|status|log}"; exit 1 ;;
esac
