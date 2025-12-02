# Тестирование Handshake протокола

## Быстрый тест

### 1. Сборка клиента

```powershell
cd C:\LostLoveProtocol\client-csharp\LLPClient
dotnet publish -c Release -r win-x64 --self-contained
```

Бинарник будет в: `bin\Release\net8.0\win-x64\publish\LLPClient.exe`

### 2. Копирование в рабочую папку

```powershell
# Создаём папку
mkdir C:\LLP -Force
mkdir C:\LLP\configs -Force

# Копируем клиент
Copy-Item bin\Release\net8.0\win-x64\publish\LLPClient.exe C:\LLP\

# Копируем существующую конфигурацию
Copy-Item bin\Release\net8.0\win-x64\publish\configs\client1.toml C:\LLP\configs\
```

### 3. Проверка сервера на VPS

```bash
# На VPS проверяем, что сервер запущен
systemctl status llp-server

# Если не запущен - запускаем
sudo systemctl start llp-server

# Смотрим логи в реальном времени
sudo journalctl -u llp-server -f
```

### 4. Запуск клиента

```powershell
# Запускаем от имени администратора
cd C:\LLP
.\LLPClient.exe
```

Или напрямую с конфигом:

```powershell
.\LLPClient.exe --config configs\client1.toml
```

## Ожидаемое поведение

### Успешный handshake

Клиент должен показать:

```
→ Подключение к 185.250.181.20:8443...
✓ TCP подключение установлено
→ Создание TUN интерфейса llp0...
⚠ TUN device: Stub implementation
✓ TUN интерфейс создан: 10.8.0.2
→ Выполнение handshake...
  → Отправка CLIENT_HELLO...
  → Ожидание SERVER_HELLO...
  ✓ Session ID: 1234567890ABCDEF
  → Отправка CLIENT_VERIFY...
  → Ожидание SERVER_VERIFY...
  ✓ Handshake успешно завершён!
✓ Handshake завершён
✓ Подключено!
```

Сервер в логах покажет:

```
INFO  llp_server::listener > Новый клиент подключился: 123.45.67.89:12345
INFO  llp_core::handshake  > Handshake completed: session_id=1234567890ABCDEF profile=VkVideo
INFO  llp_server::listener > Клиент успешно аутентифицирован
```

### Возможные ошибки

#### 1. "Unable to read data from transport connection"

**Причина:** Проблема с сетевым подключением или сервер не отвечает

**Решение:**
```powershell
# Проверка доступности сервера
Test-NetConnection 185.250.181.20 -Port 8443

# Проверка firewall на VPS
sudo ufw status
sudo ufw allow 8443/tcp
```

#### 2. "SERVER_VERIFY HMAC verification failed"

**Причина:** Несовместимость криптографии между клиентом и сервером

**Решение:** Проверить версии Rust сервера и C# клиента

#### 3. "Incomplete SERVER_HELLO"

**Причина:** Сервер отправил неполное сообщение (обрыв соединения)

**Решение:** Проверить логи сервера на ошибки

## Отладка

### Подробные логи на сервере

```bash
# Настроить уровень логирования
sudo nano /etc/systemd/system/llp-server.service

# Добавить переменную окружения
Environment="RUST_LOG=debug"

# Перезапустить
sudo systemctl daemon-reload
sudo systemctl restart llp-server
sudo journalctl -u llp-server -f
```

### Wireshark на Windows

Для анализа handshake трафика:

```powershell
# Установить Wireshark
winget install WiresharkFoundation.Wireshark

# Захват на интерфейсе к серверу
# Фильтр: tcp.port == 8443
```

Handshake должен выглядеть так:

```
1. TCP SYN/ACK (3-way handshake)
2. Client → Server: 67 bytes (CLIENT_HELLO)
3. Server → Client: 73 bytes (SERVER_HELLO)
4. Client → Server: 33 bytes (CLIENT_VERIFY)
5. Server → Client: 33 bytes (SERVER_VERIFY)
```

### Тест с netcat (проверка сервера)

```bash
# На VPS - слушаем порт
nc -l 8443 | xxd

# На Windows - отправляем CLIENT_HELLO
# (67 байт должны прийти на сервер)
```

## Верификация криптографии

### Проверка X25519 ключей

В логах сервера (если RUST_LOG=debug):

```
DEBUG X25519 public key: [32 bytes hex]
DEBUG Shared secret computed: [32 bytes hex]
DEBUG Session key derived: [32 bytes hex]
```

### Проверка HMAC

CLIENT_VERIFY и SERVER_VERIFY должны содержать 32-байтные HMAC теги.

Транскрипт для HMAC = CLIENT_HELLO (67 bytes) || SERVER_HELLO (73 bytes) = 140 bytes

## Производительность

Handshake должен занимать:

- **TCP подключение:** < 100ms
- **CLIENT_HELLO → SERVER_HELLO:** < 50ms
- **CLIENT_VERIFY → SERVER_VERIFY:** < 50ms
- **Общее время handshake:** < 200ms

Если медленнее - проверьте latency к VPS:

```powershell
Test-Connection 185.250.181.20 -Count 10
```

## Следующие шаги после успешного handshake

После успешного handshake клиент переходит в режим передачи данных.

Сейчас это заглушка, но в будущем:

1. **v1.1:** Шифрование ChaCha20-Poly1305
2. **v1.2:** Wintun для настоящего TUN интерфейса
3. **v1.3:** Мимикрия трафика (VK Video, Yandex Music, RuTube)

---

**Готово к тестированию!** 🚀
