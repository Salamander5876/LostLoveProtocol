# LostLoveProtocol (LLP)

Кастомный VPN протокол с мимикрией под российские сервисы для обхода DPI.

## Особенности

- **Криптография**: X25519, ChaCha20-Poly1305, HKDF-SHA256, Ed25519, BLAKE3
- **Мимикрия**: Имитация трафика VK Video, Яндекс.Музыка, RuTube
- **Безопасность**: Replay protection, perfect forward secrecy, zeroize для секретов
- **Производительность**: Асинхронность (Tokio), zero-copy где возможно
- **Простота использования**: Автоматическое создание конфигурации при первом запуске

## Требования

### Установка Rust

**Windows:**
```bash
# Скачать и установить rustup с https://rustup.rs/
# Или использовать winget:
winget install Rustlang.Rustup
```

**Linux:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

После установки перезапустите терминал и проверьте:
```bash
rustc --version
cargo --version
```

## Сборка

```bash
# Сборка всего workspace
cargo build --release

# Сборка только core
cargo build -p llp-core

# Запуск тестов
cargo test

# Запуск тестов с выводом
cargo test -- --nocapture
```

## Структура проекта

```
LostLoveProtocol/
├── crates/
│   ├── llp-core/           ✅ Ядро протокола
│   ├── llp-mimicry/        ✅ Система мимикрии
│   ├── llp-server/         ✅ VPN сервер
│   └── llp-client/         ✅ VPN клиент
├── installer/              ✅ Установщик для Linux
└── config/                 ✅ Примеры конфигурации
```

## Использование

### Быстрый старт

**Сервер:**
```bash
# Сборка
cargo build --release -p llp-server

# Первый запуск автоматически создаст конфигурацию
sudo ./target/release/llp-server

# Отредактируйте созданную конфигурацию
nano server.toml

# Запустите снова
sudo ./target/release/llp-server
```

**Клиент:**
```bash
# Сборка
cargo build --release -p llp-client

# Первый запуск автоматически создаст конфигурацию
sudo ./target/release/llp-client

# Отредактируйте конфигурацию и укажите адрес сервера
nano client.toml

# Запустите снова
sudo ./target/release/llp-client
```

### Автоматическая установка на Linux

```bash
cd installer
sudo bash install.sh
```

Установщик автоматически:
- Установит Rust (если не установлен)
- Скомпилирует проект
- Создаст конфигурацию
- Настроит systemd сервис
- Настроит IP forwarding и NAT

## Конфигурация

Примеры конфигурационных файлов находятся в `config/`.

## Разработка

### Запуск тестов

```bash
# Все тесты
cargo test

# Только llp-core
cargo test -p llp-core

# С подробным выводом
cargo test -- --nocapture
```

### Проверка кода

```bash
# Форматирование
cargo fmt

# Линтер
cargo clippy -- -D warnings

# Проверка документации
cargo doc --no-deps --open
```

## Безопасность

⚠️ **ВАЖНО**: Этот проект предназначен только для:
- Образовательных целей
- Авторизованного тестирования безопасности
- Легального обхода цензуры

НЕ используйте для незаконной деятельности.

## Лицензия

MIT

## Статус разработки

- [x] llp-core (ядро протокола) — 100%
- [x] llp-mimicry (система мимикрии) — 100%
- [x] llp-server (сервер) — 100%
- [x] llp-client (клиент) — 100%
- [x] Установщик — 100%

**Версия**: 0.3.0-alpha
**Статус**: ✅ Готов к тестированию

## Документация

- [PROGRESS.md](PROGRESS.md) — Подробный прогресс разработки
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) — Детальный статус реализации
- [config/server.toml.example](config/server.toml.example) — Пример конфигурации сервера
- [config/client.toml.example](config/client.toml.example) — Пример конфигурации клиента

## Статистика

| Компонент | Строк кода | Файлов | Тесты | Статус |
|-----------|------------|--------|-------|--------|
| llp-core | ~2300 | 6 | 62+ | ✅ |
| llp-mimicry | ~1200 | 9 | 30+ | ✅ |
| llp-server | ~1100 | 5 | 10+ | ✅ |
| llp-client | ~1500 | 5 | 8+ | ✅ |
| **ИТОГО** | **~6100** | **25** | **110+** | ✅ |

## Контакты

Для вопросов и предложений используйте GitHub Issues
