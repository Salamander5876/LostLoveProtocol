# Установка LLP Client на Windows - Полная инструкция

## Шаг 1: Установка Visual Studio Build Tools (обязательно!)

Rust на Windows требует MSVC компилятор для сборки нативных библиотек.

### Вариант A: Автоматическая установка (рекомендуется)

1. Скачайте установщик: https://aka.ms/vs/17/release/vs_BuildTools.exe
2. Запустите установщик
3. Выберите "C++ build tools"
4. Нажмите "Install"
5. Дождитесь завершения (~5-10 минут, ~6 GB)

### Вариант B: Через winget (если установлен)

```powershell
winget install Microsoft.VisualStudio.2022.BuildTools --force --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

### Вариант C: Установка Visual Studio Community (если нужна полная IDE)

1. Скачайте: https://visualstudio.microsoft.com/downloads/
2. При установке выберите "Desktop development with C++"

## Шаг 2: Установка Rust

1. Скачайте rustup: https://rustup.rs/
2. Запустите `rustup-init.exe`
3. Выберите вариант по умолчанию (нажмите Enter)
4. Дождитесь завершения установки

## Шаг 3: Перезапустите PowerShell

**ВАЖНО:** Закройте и откройте PowerShell заново после установки!

## Шаг 4: Соберите клиент

```powershell
cd C:\LostLoveProtocol
cargo build --release -p llp-client
```

Компиляция займёт 2-5 минут при первом запуске.

## Шаг 5: Скопируйте бинарник

```powershell
Copy-Item target\release\llp-client.exe client\llp-client.exe
```

## Шаг 6: Создайте папку для конфигураций

```powershell
New-Item -ItemType Directory -Force -Path client\configs
```

## Шаг 7: Получите конфигурацию с VPS

### На VPS экспортируйте конфигурацию:

```bash
cd ~/LostLoveProtocol
./target/release/llp-server --export-client-config client1.toml
```

### Скачайте на Windows:

**Способ 1 - SCP:**
```powershell
scp root@ваш-ip-vps:~/LostLoveProtocol/client1.toml C:\LostLoveProtocol\client\configs\
```

**Способ 2 - WinSCP:**
1. Установите WinSCP: https://winscp.net
2. Подключитесь к VPS
3. Скачайте `client1.toml` в `C:\LostLoveProtocol\client\configs\`

**Способ 3 - Копирование вручную:**
```bash
# На VPS
cat ~/LostLoveProtocol/client1.toml
```
Скопируйте вывод и создайте файл `C:\LostLoveProtocol\client\configs\client1.toml`

## Шаг 8: Запустите клиент

### Способ 1: Через PowerShell скрипт (автоматизированный)

```powershell
cd C:\LostLoveProtocol\client
.\LLP-Client.ps1
```

### Способ 2: Напрямую (простой)

```powershell
cd C:\LostLoveProtocol\client
.\llp-client.exe --config configs\client1.toml
```

## Проверка подключения

Откройте новое окно PowerShell:

```powershell
# Проверка интерфейса
ipconfig

# Ping сервера через VPN
ping 10.8.0.1

# Проверка маршрутизации
tracert 8.8.8.8
```

---

## Устранение проблем

### Ошибка "linker link.exe not found"

**Причина:** Не установлены Visual Studio Build Tools

**Решение:** Установите Build Tools (Шаг 1)

### Ошибка "execution policy"

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Rust не находит компилятор после установки Build Tools

**Решение:**
1. Закройте ВСЕ окна PowerShell
2. Откройте PowerShell заново
3. Проверьте: `cargo --version`
4. Если не помогло - перезагрузите Windows

### Компиляция зависает

**Решение:**
1. Подождите - первая компиляция занимает 5-10 минут
2. Проверьте интернет соединение
3. Очистите кэш: `cargo clean`

### Клиент не создаёт TUN интерфейс

**Решение:**
1. Убедитесь, что PowerShell запущен **от имени администратора**
2. Проверьте антивирус - добавьте `llp-client.exe` в исключения
3. Проверьте Windows Firewall

---

## Быстрая команда для проверки готовности

```powershell
# Проверка всех зависимостей
Write-Host "Проверка установки..." -ForegroundColor Cyan

# Проверка Visual Studio Build Tools
if (Test-Path "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools") {
    Write-Host "✓ Visual Studio Build Tools установлены" -ForegroundColor Green
} else {
    Write-Host "✗ Visual Studio Build Tools НЕ установлены!" -ForegroundColor Red
}

# Проверка Rust
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Host "✓ Rust установлен: $(cargo --version)" -ForegroundColor Green
} else {
    Write-Host "✗ Rust НЕ установлен!" -ForegroundColor Red
}

# Проверка llp-client
if (Test-Path "C:\LostLoveProtocol\client\llp-client.exe") {
    Write-Host "✓ LLP Client скомпилирован" -ForegroundColor Green
} else {
    Write-Host "⚠ LLP Client не найден - запустите сборку" -ForegroundColor Yellow
}
```

---

## Полная последовательность установки (краткая версия)

```powershell
# 1. Установить Build Tools
# Скачать и запустить: https://aka.ms/vs/17/release/vs_BuildTools.exe
# Выбрать: C++ build tools → Install

# 2. Установить Rust
# Скачать и запустить: https://rustup.rs/

# 3. ПЕРЕЗАПУСТИТЬ PowerShell

# 4. Собрать клиент
cd C:\LostLoveProtocol
cargo build --release -p llp-client
Copy-Item target\release\llp-client.exe client\llp-client.exe

# 5. Создать папку configs
New-Item -ItemType Directory -Force -Path client\configs

# 6. Скачать конфигурацию с VPS в client\configs\

# 7. Запустить
cd client
.\llp-client.exe --config configs\client1.toml
```

---

## Альтернатива: Использование MinGW (не рекомендуется)

Если не хотите устанавливать Visual Studio:

```powershell
# Установить MinGW через rustup
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu

# Установить MinGW
winget install -e --id msys2.msys2
```

**Примечание:** MSVC (Visual Studio) - рекомендуемый вариант для Windows.

---

Готово! После этих шагов клиент будет работать! 🚀
