# esp-wrap

Userspace Layer 3 Tunnel over Raw IP Protocol 50 (ESP)

[English version below](#english-version)

---

## Русский

### 1. Назначение

`esp-wrap` — легковесный сетевой L3-туннель, работающий в пространстве пользователя (Userspace) на языке Go непосредственно поверх сырых IP-пакетов протокола ESP (Encapsulating Security Payload, IP Protocol 50, RFC 4303).

Основное назначение:
1. **Серверные мосты (Relay VPS <-> Exit VPS):** Соединение промежуточного сервера в РФ с зарубежным сервером, на котором заблокированы входящие TCP/UDP протоколы, без потерь пакетов.
2. **Прямое клиентское подключение:** Подключение с рабочих станций или домашних роутеров при наличии публичного («белого») статического или динамического IPv4-адреса.

---

### 2. Принцип работы и стек технологий

#### 2.1. Почему Protocol 50
Блокировки ТСПУ (DPI) ориентированы на транспортные протоколы уровня L4 (TCP и UDP), анализируя сигнатуры, порты, размеры пакетов и энтропию сессий.

Protocol 50 (ESP) находится на одном уровне с TCP и UDP, но не имеет полей портов (Source/Destination Port). ТСПУ пропускает транзитный Protocol 50, так как на нем базируется критическая инфраструктура межфилиального корпоративного IPsec (банки, банкоматы, защищенные каналы предприятий).

#### 2.2. Реализация в коде
- **Userspace Raw Socket:** Работает через сырой сокет `ip4:50` (`SOCK_RAW`, `IPPROTO_ESP`) без использования ядерных политик `ip xfrm` и без тяжелых демонов (StrongSwan, Libreswan).
- **Zero-IKE:** Не открывает порты UDP 500 и 4500, устраняя главную причину блокировки классического IPsec со стороны DPI.
- **Шифрование:** Симметричное блочное шифрование AES-GCM (RFC 4106) с аппаратным ускорением AES-NI и встроенной аутентификацией пакетов (AEAD ICV).
- **Модель авторизации Reality и Forward Secrecy:** Сервер использует статическую пару ключей X25519, а клиенты авторизуются по своим `UUID`. Полноценный Forward Secrecy достигается двухэтапным обменом Диффи-Хеллмана (StaticDH + EphemeralDH).
- **Раздельные сессионные ключи (c2s / s2c):** Для исключения повтора Nonce потоки Клиент->Сервер и Сервер->Клиент шифруются независимыми ключами и солями, деривированными через стандартный HKDF-SHA256.
- **Динамический пул адресов:** Сервер автоматически выделяет клиентам IP-адреса из подсети `10.99.0.0/16` в оперативной памяти и изолирует клиентов друг от друга (client-to-client isolation).
- **Anti-Replay и Rekeying:** 64-битное скользящее окно защиты от повторов на обеих сторонах, защита от CPU-DoS через HMAC `mac1` до вызова криптографии и автоматический повторный хендшейк (Rekey) каждые 2 часа.
- **Сетевой интерфейс:** Виртуальный адаптер `TUN` (`tun-esp0`) для передачи L3 IP-трафика и встроенный прокси-сервер SOCKS5 (`127.0.0.1:10951`).

---

### 3. Где работает, а где нет

- **Работает стабильно:**
  - Канал между серверами с белыми статическими IPv4-адресами (Relay VPS в РФ <-> Exit VPS за рубежом).
  - Домашний проводной интернет с публичным («белым») статическим или динамическим IPv4-адресом.
- **НЕ работает:**
  - Мобильные сети (LTE/3G всех операторов): шлюзы операторов (PGW/GGSN) дропают пакеты без L4-портов.
  - Провайдеры с серыми IP за CGNAT (RFC 6598, `100.64.x.x` / `10.x.x.x`): стандартный PAT-маршрутизатор не может мультиплексировать Protocol 50 без поддержки IPsec ALG, либо выпускает внутренний серый IP наружу без трансляции адреса источника (SNAT), из-за чего сервер не может отправить ответ.

---

### 4. Генерация ключей и управление пользователями

Бинарники `esp-server` и `esp-client` содержат встроенные генераторы ключей:

#### 4.1. Генерация ключей сервера (X25519)
```bash
# Сгенерировать пару PrivateKey и PublicKey:
./esp-server -gen-key
# или
./esp-client -gen-key
```

#### 4.2. Генерация UUID клиента
```bash
# Сгенерировать случайный UUID:
./esp-server -gen-uuid
# или
./esp-client -gen-uuid
```

#### 4.3. Управление пользователями на сервере
```bash
# Добавить пользователя alice (генерирует UUID и создает client_alice.json):
./esp-server -c server.json -add-user alice

# Просмотреть список зарегистрированных пользователей:
./esp-server -c server.json -list-users

# Удалить пользователя:
./esp-server -c server.json -del-user alice
```

---

### 5. Режимы работы и отключение TUN / SOCKS5

Приложение поддерживает гибкую настройку сетевого окружения:

- **Отключение TUN (`-no-tun` / `"disable_tun": true`):**
  Позволяет запускать туннель без создания виртуального сетевого интерфейса `tun-esp0` и без изменения системных маршрутов. Полезно для работы в контейнерах, тестовых средах или на серверах без прав `CAP_NET_ADMIN`.
- **Отключение SOCKS5 (`-no-socks` / `"disable_socks": true`):**
  Отключает встроенный локальный SOCKS5-сервер, если туннель используется исключительно как системный сетевой L3-интерфейс.

Примеры запуска:
```bash
# Запуск клиента без создания TUN-интерфейса:
sudo ./esp-client -c client.json -no-tun

# Запуск клиента без встроенного SOCKS5:
sudo ./esp-client -c client.json -no-socks

# Запуск сервера без TUN-интерфейса:
sudo ./esp-server -c server.json -no-tun
```

---

### 6. Быстрый старт

#### 6.1. Развертывание сервера одной командой
Скрипт `scripts/deploy_new_server.sh` компилирует бинарники, загружает их на сервер, генерирует ключи, настраивает `systemd` и выгружает готовые архивы для клиентов:

```bash
./scripts/deploy_new_server.sh 198.51.100.1
# или с указанием пользователя:
./scripts/deploy_new_server.sh 198.51.100.1 ubuntu
```

Готовые клиентские пакеты сохраняются в каталоге `generated_clients/198.51.100.1/`.

#### 6.2. Сборка из исходников
```bash
git clone https://github.com/CoCisochki/esp-wrap.git
cd esp-wrap

make test   # Запуск тестов
make build  # Сборка bin/esp-server и bin/esp-client
```

#### 6.3. Удаленное управление клиентами
```bash
# Создать нового клиента bob и получить его архив:
./scripts/manage_users.sh add bob 198.51.100.1

# Список клиентов на сервере:
./scripts/manage_users.sh list 198.51.100.1

# Удалить клиента:
./scripts/manage_users.sh del bob 198.51.100.1
```

#### 6.4. Запуск клиента
Клиентский пакет распаковывается на Linux-машине и управляется скриптом `run.sh`:

```bash
sudo ./run.sh start   # Запуск в фоновом режиме
sudo ./run.sh status  # Проверка статуса, пинга и SOCKS5
sudo ./run.sh log     # Просмотр логов в реальном времени
sudo ./run.sh stop    # Остановка сервиса
```

---

### 7. Примеры конфигурационных файлов

#### `server.json`
```json
{
  "listen_addr": "0.0.0.0",
  "tun_name": "tun-esp0",
  "tun_ip": "10.99.0.1",
  "tun_cidr": 16,
  "tun_mtu": 1360,
  "disable_tun": false,
  "private_key": "BASE64_SERVER_PRIVATE_KEY",
  "public_key": "BASE64_SERVER_PUBLIC_KEY",
  "clients": [
    {
      "name": "alice",
      "uuid": "c3b5d2e1-4a6f-4c8d-9e0a-1b2c3d4e5f60"
    }
  ]
}
```

#### `client.json`
```json
{
  "server_addr": "198.51.100.1",
  "server_public_key": "BASE64_SERVER_PUBLIC_KEY",
  "uuid": "c3b5d2e1-4a6f-4c8d-9e0a-1b2c3d4e5f60",
  "bind_interface": "",
  "gateway": "10.99.0.1",
  "tun_name": "tun-esp0",
  "tun_mtu": 1360,
  "disable_tun": false,
  "keepalive_seconds": 25,
  "socks_listen": "127.0.0.1:10951"
}
```

---

### 8. Производительность и бенчмарки

Тестирование проводилось в изолированных сетевых пространствах имён (`ip netns`) в среде Linux с изоляцией ресурсов под конфигурацию 2 vCPU / 2 GB RAM (процессы `esp-server` и `esp-client` привязаны ровно к двум ядрам CPU через `taskset`):

#### 8.1. Одиночный TCP-поток (Single Stream)
| Скорость канала | Throughput | Нагрузка сервера (% 1 vCPU) | Нагрузка сервера на VPS (2 vCPU) | Нагрузка клиента (% 1 vCPU) | Retransmits | RAM (сервер) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **100 Мбит/с** | 91.0 Мбит/с | 16.1% | **8.1%** | 11.0% | 26 | 12.6 МБ |
| **250 Мбит/с** | 227.6 Мбит/с | 36.2% | **18.1%** | 24.2% | 58 | 12.4 МБ |
| **500 Мбит/с** | 455.3 Мбит/с | 61.9% | **30.9%** | 38.4% | 599 | 12.7 МБ |
| **1 Гбит/с** | 910.8 Мбит/с | 97.0% | **48.5%** | 63.6% | 1019 | 12.7 МБ |
| **Без ограничений** | 1578.4 Мбит/с | 89.9% | **45.0%** | 80.0% | 110 | 12.6 МБ |

#### 8.2. Два параллельных потока (`iperf3 -P 2`)
| Скорость канала | Throughput | Нагрузка сервера на VPS (2 vCPU) | Нагрузка клиента на VPS (2 vCPU) | Retransmits |
| :--- | :--- | :--- | :--- | :--- |
| **250 Мбит/с** | 227.6 Мбит/с | **18.1%** | **12.1%** | 58 |
| **500 Мбит/с** | 455.3 Мбит/с | **31.1%** | **18.9%** | 111 |
| **1 Гбит/с** | 910.7 Мбит/с | **46.7%** | **30.2%** | 1079 |
| **Без ограничений** | 1610.8 Мбит/с | **45.5%** | **39.9%** | 401 |

#### 8.3. Полный дуплекс (Bidirectional `--bidir`, одновременная передача и приём)
| Скорость канала | Throughput (DL + UL) | Нагрузка сервера на VPS (2 vCPU) | Нагрузка клиента на VPS (2 vCPU) | RAM (сервер) |
| :--- | :--- | :--- | :--- | :--- |
| **250 Мбит/с** | 214.7 Мбит/с | **22.4%** | **18.6%** | 12.5 МБ |
| **500 Мбит/с** | 443.1 Мбит/с | **32.6%** | **23.9%** | 12.7 МБ |
| **Без ограничений** | 886.0 Мбит/с | **50.6%** | **45.0%** | 12.6 МБ |

Ключевые оптимизации:
- **Zero-Allocation Data Path:** Устранено создание объектов в куче во время передачи данных (`sync.Pool` и переиспользуемые буферы).
- **Lock-Free Crypto Context:** Поиск активных сессий и шифров выполняется через `atomic.Pointer` без использования мьютексов.
- **Стабильный объем памяти:** Потребление оперативной памяти составляет 12–14 МБ вне зависимости от объема переданного трафика.

---
---

<a name="english-version"></a>
## English

### 1. Purpose & Overview

`esp-wrap` is a lightweight, userspace Layer 3 network tunnel written in Go that encapsulates traffic directly inside raw IP Encapsulating Security Payload packets (ESP, IP Protocol 50, RFC 4303).

Primary use cases:
1. **Server-to-Server Relay Bridges:** Interconnecting an unrestricted domestic Relay VPS with a blocked Exit VPS abroad where standard TCP/UDP traffic is blocked, without packet drops.
2. **Direct Client Access:** Connecting workstations or home routers possessing a dedicated public ("white") IPv4 address.

---

### 2. Architecture & Implementation

#### 2.1. Why Protocol 50
DPI middleboxes primarily target transport layer (L4) protocols (TCP and UDP) by inspecting handshakes, port ranges, and flow entropy.

Protocol 50 (ESP) operates at the same IP transport layer as TCP and UDP but lacks port fields (Source/Destination Port). Middleboxes routinely forward Protocol 50 to maintain inter-branch corporate IPsec infrastructure (banking networks, ATMs, enterprise links).

#### 2.2. Engineering Stack
- **Userspace Raw Sockets:** Operates on an `ip4:50` raw socket (`SOCK_RAW`, `IPPROTO_ESP`) without kernel `ip xfrm` state policies or heavy daemons (StrongSwan, Libreswan).
- **Zero-IKE Design:** Avoids UDP ports 500 and 4500 entirely, bypassing IKE inspection and state tracking.
- **Authenticated Encryption:** AES-GCM (RFC 4106) with hardware AES-NI acceleration and integrated ICV tag authentication.
- **Reality Authorization Model & Forward Secrecy:** The server maintains a static X25519 keypair, while clients authenticate using individual `UUID` values. True Forward Secrecy is achieved via dual Diffie-Hellman exchanges (StaticDH + EphemeralDH).
- **Directional Session Keys (c2s / s2c):** Eliminates nonce reuse by deriving strictly independent keys, salts, and IV bases for Client->Server and Server->Client flows using standard HKDF-SHA256.
- **Dynamic IP Allocation:** In-memory `/16` subnet dynamic pool with client-to-client isolation enforced in userspace.
- **Anti-Replay Mechanism & Rekeying:** 64-bit sliding window bitmap on both endpoints, pre-ECDH CPU-DoS protection via HMAC `mac1`, and automatic rekeying every 2 hours.
- **Network Interface:** Virtual `TUN` adapter (`tun-esp0`) and an integrated local SOCKS5 proxy (`127.0.0.1:10951`).

---

### 3. Network Compatibility

- **Supported Environments:**
  - Server-to-server links with static public IPv4 addresses.
  - Residential internet connections with a public (static or dynamic) IPv4 address.
- **Unsupported Environments:**
  - Cellular networks (LTE / 3G / 5G): Mobile carrier gateways (PGW/GGSN) drop portless L4 packets.
  - ISPs utilizing CGNAT without IPsec ALG (RFC 6598): Standard PAT cannot multiplex portless ESP packets, or fails to perform SNAT, leaking private RFC 1918 addresses into transit networks.

---

### 4. Key Management & User Provisioning

Both `esp-server` and `esp-client` contain built-in key generation utilities:

#### 4.1. Server Key Generation (X25519)
```bash
# Generate a new PrivateKey and PublicKey pair:
./esp-server -gen-key
# or
./esp-client -gen-key
```

#### 4.2. Client UUID Generation
```bash
# Generate a random client UUID:
./esp-server -gen-uuid
# or
./esp-client -gen-uuid
```

#### 4.3. User Management on Server
```bash
# Provision user alice (generates UUID and client_alice.json):
./esp-server -c server.json -add-user alice

# List provisioned users:
./esp-server -c server.json -list-users

# Remove a user:
./esp-server -c server.json -del-user alice
```

---

### 5. Operating Modes: Disabling TUN / SOCKS5

The runtime supports decoupled operational modes:

- **Disable TUN (`-no-tun` / `"disable_tun": true`):**
  Runs the tunnel without creating a virtual `tun-esp0` adapter or modifying host routing tables. Useful in containers or unprivileged environments.
- **Disable SOCKS5 (`-no-socks` / `"disable_socks": true`):**
  Disables the embedded SOCKS5 proxy service when operating solely as a network interface.

Usage examples:
```bash
# Run client without TUN interface:
sudo ./esp-client -c client.json -no-tun

# Run client without embedded SOCKS5 proxy:
sudo ./esp-client -c client.json -no-socks

# Run server without TUN interface:
sudo ./esp-server -c server.json -no-tun
```

---

### 6. Quickstart Guide

#### 6.1. Automated Single-Command Deployment
Use `scripts/deploy_new_server.sh` to compile, provision, and configure the remote node:

```bash
./scripts/deploy_new_server.sh 198.51.100.1
# or specifying a custom user:
./scripts/deploy_new_server.sh 198.51.100.1 ubuntu
```

Client configuration bundles are saved to `generated_clients/198.51.100.1/`.

#### 6.2. Manual Build
```bash
git clone https://github.com/CoCisochki/esp-wrap.git
cd esp-wrap

make test   # Execute test suite
make build  # Compile bin/esp-server and bin/esp-client
```

#### 6.3. Remote User Management
```bash
# Add a new client profile:
./scripts/manage_users.sh add bob 198.51.100.1

# List active profiles:
./scripts/manage_users.sh list 198.51.100.1

# Delete profile:
./scripts/manage_users.sh del bob 198.51.100.1
```

#### 6.4. Running the Client
```bash
sudo ./run.sh start   # Start daemon in background
sudo ./run.sh status  # Verify tunnel and SOCKS5 status
sudo ./run.sh log     # View real-time logs
sudo ./run.sh stop    # Stop daemon
```

---

### 7. Configuration Reference

#### `server.json`
```json
{
  "listen_addr": "0.0.0.0",
  "tun_name": "tun-esp0",
  "tun_ip": "10.99.0.1",
  "tun_cidr": 16,
  "tun_mtu": 1360,
  "disable_tun": false,
  "private_key": "BASE64_SERVER_PRIVATE_KEY",
  "public_key": "BASE64_SERVER_PUBLIC_KEY",
  "clients": [
    {
      "name": "alice",
      "uuid": "c3b5d2e1-4a6f-4c8d-9e0a-1b2c3d4e5f60"
    }
  ]
}
```

#### `client.json`
```json
{
  "server_addr": "198.51.100.1",
  "server_public_key": "BASE64_SERVER_PUBLIC_KEY",
  "uuid": "c3b5d2e1-4a6f-4c8d-9e0a-1b2c3d4e5f60",
  "bind_interface": "",
  "gateway": "10.99.0.1",
  "tun_name": "tun-esp0",
  "tun_mtu": 1360,
  "disable_tun": false,
  "keepalive_seconds": 25,
  "socks_listen": "127.0.0.1:10951"
}
```

---

### 8. Performance & Benchmarks

Benchmarking was conducted in isolated Linux network namespaces (`ip netns`) configured to emulate a standard 2 vCPU / 2 GB RAM server instance (both `esp-server` and `esp-client` pinned strictly to two CPU cores via `taskset`):

#### 8.1. Single Stream TCP
| Link Target | Throughput | Server CPU (% 1 vCPU) | Server Load on 2 vCPU VPS | Client CPU (% 1 vCPU) | Retransmits | Server RAM |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **100 Mbps** | 91.0 Mbps | 16.1% | **8.1%** | 11.0% | 26 | 12.6 MB |
| **250 Mbps** | 227.6 Mbps | 36.2% | **18.1%** | 24.2% | 58 | 12.4 MB |
| **500 Mbps** | 455.3 Mbps | 61.9% | **30.9%** | 38.4% | 599 | 12.7 MB |
| **1000 Mbps (1 Gbps)** | 910.8 Mbps | 97.0% | **48.5%** | 63.6% | 1019 | 12.7 MB |
| **Uncapped** | 1578.4 Mbps | 89.9% | **45.0%** | 80.0% | 110 | 12.6 MB |

#### 8.2. Two Parallel Streams (`iperf3 -P 2`)
| Link Target | Throughput | Server Load on 2 vCPU VPS | Client Load on 2 vCPU VPS | Retransmits |
| :--- | :--- | :--- | :--- | :--- |
| **250 Mbps** | 227.6 Mbps | **18.1%** | **12.1%** | 58 |
| **500 Mbps** | 455.3 Mbps | **31.1%** | **18.9%** | 111 |
| **1000 Mbps** | 910.7 Mbps | **46.7%** | **30.2%** | 1079 |
| **Uncapped** | 1610.8 Mbps | **45.5%** | **39.9%** | 401 |

#### 8.3. Full-Duplex Bidirectional (`--bidir`)
| Link Target | Total Throughput (DL + UL) | Server Load on 2 vCPU VPS | Client Load on 2 vCPU VPS | Server RAM |
| :--- | :--- | :--- | :--- | :--- |
| **250 Mbps** | 214.7 Mbps | **22.4%** | **18.6%** | 12.5 MB |
| **500 Mbps** | 443.1 Mbps | **32.6%** | **23.9%** | 12.7 MB |
| **Uncapped** | 886.0 Mbps | **50.6%** | **45.0%** | 12.6 MB |

Architecture highlights:
- **Zero-Allocation Data Path:** Heap allocations during packet processing are eliminated using `sync.Pool` and preallocated per-worker buffers.
- **Lock-Free Cryptographic State:** Cryptographic contexts and active sessions use `atomic.Pointer` for concurrent zero-contention lookups.
- **Deterministic Padding:** RFC 4303 sequential padding and sequence-derived jitter replace kernel entropy syscalls on the packet datapath.
- **Low Memory Footprint:** Stable resident memory usage of 12–14 MB under continuous full-rate load.
