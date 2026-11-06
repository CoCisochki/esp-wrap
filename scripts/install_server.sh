#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "[!] Этот скрипт должен быть запущен с правами root!"
    exec sudo bash "$0" "$@"
fi

INSTALL_DIR="/opt/esp-wrap"
mkdir -p "$INSTALL_DIR"

echo "=========================================================="
echo "    Установка ESP-Wrap Server (IPsec Protocol 50)         "
echo "=========================================================="

echo "[1/6] Определение сетевых адресов сервера..."
PRIMARY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
RAW_IPS=($(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1))
ALL_IPS=()
for ip in "${RAW_IPS[@]}"; do
    if [[ ! "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.) ]]; then
        ALL_IPS+=("$ip")
    fi
done
if [ ${#ALL_IPS[@]} -eq 0 ] && [ -n "$PRIMARY_IP" ]; then
    ALL_IPS+=("$PRIMARY_IP")
fi

echo "[-] Основной публичный IP:  $PRIMARY_IP"
echo "[-] Все внешние публичные IP: ${ALL_IPS[*]}"

if [ ${#ALL_IPS[@]} -gt 1 ]; then
    echo "[i] Обнаружено несколько внешних IP (${#ALL_IPS[@]} шт.)."
    echo "    esp-server слушает 0.0.0.0 (Protocol 50), поэтому клиенты могут"
    echo "    подключаться на ЛЮБОЙ из этих адресов:"
    for ip in "${ALL_IPS[@]}"; do
        echo "     -> $ip"
    done
fi

echo "[2/6] Настройка ядра (sysctl и xfrm)..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

ip xfrm state flush 2>/dev/null || true
ip xfrm policy flush 2>/dev/null || true

echo "[3/6] Проверка бинарника esp-server..."
systemctl stop esp-server.service 2>/dev/null || true
pkill -f "/opt/esp-wrap/esp-server" 2>/dev/null || true

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC=""
if [ -f "$SCRIPT_DIR/esp-server" ]; then
    BIN_SRC="$SCRIPT_DIR/esp-server"
elif [ -f "$SCRIPT_DIR/bin/esp-server" ]; then
    BIN_SRC="$SCRIPT_DIR/bin/esp-server"
elif [ -f "./esp-server" ]; then
    BIN_SRC="./esp-server"
elif [ -f "$INSTALL_DIR/esp-server" ]; then
    echo "[-] Используем существующий $INSTALL_DIR/esp-server"
elif command -v go >/dev/null 2>&1; then
    echo "[-] Компилируем esp-server из исходников..."
    CGO_ENABLED=0 go build -ldflags="-s -w" -o "$INSTALL_DIR/esp-server.new" ./cmd/esp-server
    mv -f "$INSTALL_DIR/esp-server.new" "$INSTALL_DIR/esp-server"
else
    echo "[!] Ошибка: бинарник esp-server не найден в $SCRIPT_DIR и Go не установлен!"
    echo "    Скопируйте скомпилированный bin/esp-server в $INSTALL_DIR/esp-server"
    exit 1
fi

if [ -n "$BIN_SRC" ]; then
    cp -f "$BIN_SRC" "$INSTALL_DIR/esp-server.new"
    mv -f "$INSTALL_DIR/esp-server.new" "$INSTALL_DIR/esp-server"
fi
chmod +x "$INSTALL_DIR/esp-server"

echo "[4/6] Настройка единого Private Key и генерация UUID клиентов..."
KEY_OUT=$("$INSTALL_DIR/esp-server" -gen-key)
SERVER_PRIV=$(echo "$KEY_OUT" | grep 'PrivateKey:' | awk '{print $2}')
SERVER_PUB=$(echo "$KEY_OUT" | grep 'PublicKey:' | awk '{print $2}')

cat << EOF > "$INSTALL_DIR/server.json"
{
  "listen_addr": "0.0.0.0",
  "tun_name": "tun-esp0",
  "tun_ip": "10.99.0.1",
  "tun_cidr": 16,
  "tun_mtu": 1360,
  "private_key": "${SERVER_PRIV}",
  "public_key": "${SERVER_PUB}",
  "clients": []
}
EOF

# Добавляем User 1
"$INSTALL_DIR/esp-server" -c "$INSTALL_DIR/server.json" -add-user user1 >/dev/null

# Добавляем User 2
"$INSTALL_DIR/esp-server" -c "$INSTALL_DIR/server.json" -add-user user2 >/dev/null

# Если есть второй публичный IP, назначаем его User 2 для разделения адресов
IP_CLIENT1="${ALL_IPS[0]:-$PRIMARY_IP}"
IP_CLIENT2="${ALL_IPS[1]:-${ALL_IPS[0]:-$PRIMARY_IP}}"

sed -i "s/\"server_addr\": \".*\"/\"server_addr\": \"${IP_CLIENT1}\"/" "$INSTALL_DIR/client_user1.json"
sed -i "s/\"server_addr\": \".*\"/\"server_addr\": \"${IP_CLIENT2}\"/" "$INSTALL_DIR/client_user2.json"

chmod 600 "$INSTALL_DIR"/*.json

echo "[5/6] Создание и запуск systemd-юнита esp-server.service..."
cat << EOF > /etc/systemd/system/esp-server.service
[Unit]
Description=ESP-Wrap Server (RFC 4303 IPsec Tunnel)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/esp-server -c ${INSTALL_DIR}/server.json
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable esp-server.service >/dev/null 2>&1 || true
systemctl restart esp-server.service

echo "[6/6] Проверка работы сервера..."
sleep 2
if systemctl is-active --quiet esp-server.service; then
    echo "[+] esp-server.service успешно активен и работает!"
else
    echo "[!] Внимание: esp-server.service не перешел в состояние active. Журнал:"
    journalctl -u esp-server.service -n 20 --no-pager
    exit 1
fi

echo "=========================================================="
echo "          СЕРВЕР УСПЕШНО РАЗВЕРНУТ И ГОТОВ К РАБОТЕ        "
echo "=========================================================="
echo "Интерфейс туннеля: 10.99.0.1/16 (tun-esp0)"
echo "Server Public Key:      ${SERVER_PUB}"
echo "Конфигурация сервера:   $INSTALL_DIR/server.json"
echo ""
echo "Создано 2 изолированных клиентских профиля (VLESS Reality ECDH модель):"
echo "----------------------------------------------------------"
echo "[+] КЛИЕНТ 1 (user1):"
echo "    Файл: $INSTALL_DIR/client_user1.json"
echo "    Серверный эндпоинт: ${IP_CLIENT1}"
echo ""
echo "[+] КЛИЕНТ 2 (user2):"
echo "    Файл: $INSTALL_DIR/client_user2.json"
echo "    Серверный эндпоинт: ${IP_CLIENT2}"
echo "----------------------------------------------------------"
echo "IP выдается динамически и случайно из пула 10.99.0.0/16 при каждом подключении."
echo "Клиенты изолированы друг от друга (client-to-client isolation)."
echo "=========================================================="
