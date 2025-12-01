# LostLoveProtocol (LLP)

Кастомный VPN протокол с мимикрией под российские сервисы для обхода DPI.

## Особенности

- **Криптография**: X25519, ChaCha20-Poly1305, HKDF-SHA256, Ed25519, BLAKE3
- **Мимикрия**: Имитация трафика VK Video, Яндекс.Музыка, RuTube
- **Безопасность**: Replay protection, perfect forward secrecy, zeroize для секретов
- **Производительность**: Асинхронность (Tokio), zero-copy где возможно

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
llp/
├── crates/
│   ├── llp-core/           # Ядро протокола
│   ├── llp-mimicry/        # Система мимикрии
│   ├── llp-server/         # Серверная часть
│   └── llp-client/         # Клиентская часть
└── installer/              # Установщик для Linux
```

## Использование

### Запуск сервера

```bash
cargo run -p llp-server -- --config server.toml
```

### Подключение клиента

```bash
cargo run -p llp-client -- --config client.toml
```

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

- [x] llp-core (ядро протокола)
- [ ] llp-mimicry (система мимикрии)
- [ ] llp-server (сервер)
- [ ] llp-client (клиент)
- [ ] Установщик

## Контакты

GitHub Issues: https://github.com/yourusername/llp/issues
