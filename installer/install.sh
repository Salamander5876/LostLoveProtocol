#!/bin/bash
# Установщик LostLoveProtocol Server для Debian/Ubuntu
# Использование: sudo bash install.sh

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Ошибка: Запустите скрипт с правами root (sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    LostLoveProtocol Server - Установщик          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# Определение дистрибутива
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo -e "${RED}Не удалось определить дистрибутив${NC}"
    exit 1
fi

echo -e "${YELLOW}→${NC} Обнаружен: $PRETTY_NAME"

# Проверка поддержки
if [[ "$OS" != "ubuntu" ]] && [[ "$OS" != "debian" ]]; then
    echo -e "${RED}Ошибка: Поддерживаются только Ubuntu и Debian${NC}"
    exit 1
fi

# Функция вывода шага
step() {
    echo ""
    echo -e "${GREEN}▸${NC} $1"
}

# Шаг 1: Установка зависимостей
step "Установка зависимостей..."

apt-get update -qq
apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    git \
    iptables \
    net-tools

# Шаг 2: Установка Rust
step "Установка Rust..."

if ! command -v cargo &> /dev/null; then
    echo "Rust не установлен, устанавливаем..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust уже установлен: $(rustc --version)"
fi

# Шаг 3: Клонирование и сборка проекта
step "Сборка LLP Server..."

PROJECT_DIR="/opt/llp-server"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/llp-server"
LOG_DIR="/var/log/llp-server"

# Создание директорий
mkdir -p "$PROJECT_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"

# Копирование исходников (если запускаем из репозитория)
if [ -f "../Cargo.toml" ]; then
    echo "Копирование исходников..."
    cp -r ../* "$PROJECT_DIR/"
    cd "$PROJECT_DIR"
else
    echo -e "${YELLOW}Внимание: Запускайте скрипт из директории installer/${NC}"
    exit 1
fi

# Сборка в release режиме
echo "Компиляция... (может занять несколько минут)"
cargo build --release --bin llp-server

# Копирование бинарника
cp target/release/llp-server "$BIN_DIR/llp-server"
chmod +x "$BIN_DIR/llp-server"

echo -e "${GREEN}✓${NC} Бинарник установлен: $BIN_DIR/llp-server"

# Шаг 4: Генерация конфигурации
step "Генерация конфигурации..."

if [ ! -f "$CONFIG_DIR/server.toml" ]; then
    llp-server --generate-config "$CONFIG_DIR/server.toml"
    echo -e "${GREEN}✓${NC} Конфигурация создана: $CONFIG_DIR/server.toml"
else
    echo -e "${YELLOW}⚠${NC} Конфигурация уже существует, пропускаем"
fi

# Шаг 5: Создание systemd service
step "Создание systemd сервиса..."

cat > /etc/systemd/system/llp-server.service <<EOF
[Unit]
Description=LostLoveProtocol VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=$BIN_DIR/llp-server --config $CONFIG_DIR/server.toml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Ограничения безопасности
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "${GREEN}✓${NC} Systemd сервис создан"

# Шаг 6: Настройка IP forwarding и iptables
step "Настройка IP forwarding..."

# Включение IP forwarding
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
fi

echo -e "${GREEN}✓${NC} IP forwarding включен"

# Шаг 7: Настройка iptables для NAT
step "Настройка iptables (NAT)..."

# Определение основного сетевого интерфейса
MAIN_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

if [ -z "$MAIN_IFACE" ]; then
    echo -e "${YELLOW}⚠${NC} Не удалось определить основной интерфейс, используйте eth0"
    MAIN_IFACE="eth0"
fi

echo "Основной интерфейс: $MAIN_IFACE"

# Настройка NAT
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$MAIN_IFACE" -j MASQUERADE
iptables -A FORWARD -i tun0 -o "$MAIN_IFACE" -j ACCEPT
iptables -A FORWARD -i "$MAIN_IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Сохранение правил iptables
if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables.rules

    # Создание скрипта для автоматической загрузки правил
    cat > /etc/network/if-pre-up.d/iptables <<EOF
#!/bin/bash
iptables-restore < /etc/iptables.rules
EOF
    chmod +x /etc/network/if-pre-up.d/iptables
fi

echo -e "${GREEN}✓${NC} iptables настроены"

# Шаг 8: Завершение
step "Установка завершена!"

echo ""
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}     LLP Server успешно установлен!                ${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo "📁 Конфигурация: $CONFIG_DIR/server.toml"
echo "📁 Логи: $LOG_DIR/"
echo "📁 Бинарник: $BIN_DIR/llp-server"
echo ""
echo "Управление сервисом:"
echo "  • Запуск:      sudo systemctl start llp-server"
echo "  • Остановка:   sudo systemctl stop llp-server"
echo "  • Перезапуск:  sudo systemctl restart llp-server"
echo "  • Автозапуск:  sudo systemctl enable llp-server"
echo "  • Статус:      sudo systemctl status llp-server"
echo "  • Логи:        sudo journalctl -u llp-server -f"
echo ""
echo -e "${YELLOW}⚠${NC} Перед запуском отредактируйте конфигурацию:"
echo "   sudo nano $CONFIG_DIR/server.toml"
echo ""
echo -e "${YELLOW}⚠${NC} Не забудьте открыть порт в файрволе:"
echo "   sudo ufw allow 8443/tcp"
echo ""
echo -e "${GREEN}Готово!${NC}"
