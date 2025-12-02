#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LostLoveProtocol Client - Консольный VPN клиент с красивым меню
.DESCRIPTION
    Автоматическая установка зависимостей, управление конфигурациями и подключениями
.NOTES
    Требуются права администратора для создания TUN интерфейса
#>

# ============================================================================
# Константы и настройки
# ============================================================================

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$CONFIG_DIR = Join-Path $SCRIPT_DIR "configs"
$LLP_CLIENT_PATH = Join-Path $SCRIPT_DIR "llp-client.exe"
$RUSTUP_URL = "https://win.rustup.rs/x86_64"

# ============================================================================
# Утилиты для красивого вывода
# ============================================================================

function Write-ColorBox {
    param(
        [string]$Text,
        [ConsoleColor]$Color = 'Cyan',
        [char]$BorderChar = '═'
    )

    $width = 60
    $border = $BorderChar * $width

    Write-Host "╔$border╗" -ForegroundColor $Color
    Write-Host "║" -ForegroundColor $Color -NoNewline
    Write-Host ("{0,-$width}" -f " $Text") -NoNewline
    Write-Host "║" -ForegroundColor $Color
    Write-Host "╚$border╝" -ForegroundColor $Color
}

function Write-Step {
    param([string]$Text)
    Write-Host "`n▸ " -ForegroundColor Green -NoNewline
    Write-Host $Text -ForegroundColor White
}

function Write-Success {
    param([string]$Text)
    Write-Host "✓ " -ForegroundColor Green -NoNewline
    Write-Host $Text -ForegroundColor White
}

function Write-Error-Custom {
    param([string]$Text)
    Write-Host "✗ " -ForegroundColor Red -NoNewline
    Write-Host $Text -ForegroundColor White
}

function Write-Warning-Custom {
    param([string]$Text)
    Write-Host "⚠ " -ForegroundColor Yellow -NoNewline
    Write-Host $Text -ForegroundColor White
}

function Write-Info {
    param([string]$Text)
    Write-Host "ℹ " -ForegroundColor Cyan -NoNewline
    Write-Host $Text -ForegroundColor White
}

function Clear-Screen {
    Clear-Host
    Write-Host ""
    Write-ColorBox "LostLoveProtocol VPN Client v0.3.0" -Color Magenta
    Write-Host ""
}

# ============================================================================
# Проверка зависимостей
# ============================================================================

function Test-Rust {
    try {
        $null = Get-Command cargo -ErrorAction Stop
        $version = cargo --version 2>$null
        Write-Success "Rust установлен: $version"
        return $true
    }
    catch {
        Write-Warning-Custom "Rust не установлен"
        return $false
    }
}

function Install-Rust {
    Write-Step "Установка Rust..."

    $tempFile = Join-Path $env:TEMP "rustup-init.exe"

    try {
        Write-Info "Скачивание rustup-init.exe..."
        Invoke-WebRequest -Uri $RUSTUP_URL -OutFile $tempFile -UseBasicParsing

        Write-Info "Запуск установщика Rust..."
        Start-Process -FilePath $tempFile -ArgumentList "-y" -Wait -NoNewWindow

        # Обновление PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path += ";$env:USERPROFILE\.cargo\bin"

        Write-Success "Rust успешно установлен"

        Remove-Item $tempFile -Force
        return $true
    }
    catch {
        Write-Error-Custom "Ошибка установки Rust: $_"
        return $false
    }
}

function Test-LlpClient {
    if (Test-Path $LLP_CLIENT_PATH) {
        Write-Success "LLP Client найден: $LLP_CLIENT_PATH"
        return $true
    }
    else {
        Write-Warning-Custom "LLP Client не найден: $LLP_CLIENT_PATH"
        return $false
    }
}

function Build-LlpClient {
    Write-Step "Сборка LLP Client..."

    $projectRoot = Split-Path -Parent $SCRIPT_DIR

    if (-not (Test-Path (Join-Path $projectRoot "Cargo.toml"))) {
        Write-Error-Custom "Не найден Cargo.toml в корне проекта"
        return $false
    }

    try {
        Push-Location $projectRoot

        Write-Info "Компиляция проекта (это может занять несколько минут)..."
        cargo build --release -p llp-client 2>&1 | Out-Null

        $builtClient = Join-Path $projectRoot "target\release\llp-client.exe"

        if (Test-Path $builtClient) {
            Copy-Item $builtClient $LLP_CLIENT_PATH -Force
            Write-Success "LLP Client успешно скомпилирован"
            return $true
        }
        else {
            Write-Error-Custom "Сборка завершилась, но бинарник не найден"
            return $false
        }
    }
    catch {
        Write-Error-Custom "Ошибка сборки: $_"
        return $false
    }
    finally {
        Pop-Location
    }
}

function Initialize-Dependencies {
    Clear-Screen
    Write-Step "Проверка зависимостей..."
    Write-Host ""

    # Проверка Rust
    if (-not (Test-Rust)) {
        $install = Read-Host "Установить Rust? (Y/n)"
        if ($install -ne 'n') {
            if (-not (Install-Rust)) {
                Write-Error-Custom "Не удалось установить Rust"
                return $false
            }
        }
        else {
            Write-Error-Custom "Rust необходим для работы"
            return $false
        }
    }

    # Проверка LLP Client
    if (-not (Test-LlpClient)) {
        $build = Read-Host "Собрать LLP Client? (Y/n)"
        if ($build -ne 'n') {
            if (-not (Build-LlpClient)) {
                Write-Error-Custom "Не удалось собрать LLP Client"
                return $false
            }
        }
        else {
            Write-Error-Custom "LLP Client необходим для работы"
            return $false
        }
    }

    # Создание папки configs
    if (-not (Test-Path $CONFIG_DIR)) {
        New-Item -ItemType Directory -Path $CONFIG_DIR | Out-Null
        Write-Success "Создана папка configs: $CONFIG_DIR"
    }

    Write-Host ""
    Write-Success "Все зависимости проверены!"
    Start-Sleep -Seconds 2

    return $true
}

# ============================================================================
# Управление конфигурациями
# ============================================================================

function Get-ConfigFiles {
    if (-not (Test-Path $CONFIG_DIR)) {
        return @()
    }

    return Get-ChildItem -Path $CONFIG_DIR -Filter "*.toml" | Sort-Object Name
}

function Show-ConfigMenu {
    $configs = Get-ConfigFiles

    Clear-Screen
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "                  ДОСТУПНЫЕ КОНФИГУРАЦИИ                    " -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

    if ($configs.Count -eq 0) {
        Write-Host "║" -ForegroundColor Cyan -NoNewline
        Write-Host "          Нет доступных конфигураций                        " -NoNewline
        Write-Host "║" -ForegroundColor Cyan
        Write-Host "║" -ForegroundColor Cyan -NoNewline
        Write-Host "                                                            " -NoNewline
        Write-Host "║" -ForegroundColor Cyan
        Write-Host "║" -ForegroundColor Cyan -NoNewline
        Write-Host "  Поместите .toml файлы в папку:                           " -NoNewline
        Write-Host "║" -ForegroundColor Cyan
        Write-Host "║" -ForegroundColor Cyan -NoNewline
        Write-Host "  $CONFIG_DIR" -NoNewline
        $padding = 60 - $CONFIG_DIR.Length - 2
        Write-Host (" " * $padding) -NoNewline
        Write-Host "║" -ForegroundColor Cyan
    }
    else {
        for ($i = 0; $i -lt $configs.Count; $i++) {
            $num = $i + 1
            $name = $configs[$i].BaseName
            $size = [math]::Round($configs[$i].Length / 1KB, 2)

            Write-Host "║" -ForegroundColor Cyan -NoNewline
            Write-Host (" [{0}] " -f $num) -ForegroundColor Yellow -NoNewline
            Write-Host ("{0,-40}" -f $name) -NoNewline
            Write-Host ("{0,10} KB" -f $size) -ForegroundColor Gray -NoNewline
            Write-Host " ║" -ForegroundColor Cyan
        }
    }

    Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host " [R] Обновить список  [Q] Выход                             " -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    return $configs
}

# ============================================================================
# Подключение к VPN
# ============================================================================

function Connect-Vpn {
    param([string]$ConfigPath)

    Clear-Screen

    $configName = (Get-Item $ConfigPath).BaseName

    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "                    ПОДКЛЮЧЕНИЕ К VPN                       " -NoNewline
    Write-Host "║" -ForegroundColor Green
    Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host " Конфигурация: $configName" -NoNewline
    $padding = 60 - $configName.Length - 15
    Write-Host (" " * $padding) -NoNewline
    Write-Host "║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    Write-Info "Запуск LLP Client..."
    Write-Warning-Custom "Нажмите Ctrl+C для отключения"
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""

    try {
        & $LLP_CLIENT_PATH --config $ConfigPath
    }
    catch {
        Write-Host ""
        Write-Error-Custom "Ошибка подключения: $_"
    }
    finally {
        Write-Host ""
        Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
        Write-Host ""
        Write-Info "Подключение завершено"
        Write-Host ""
        Read-Host "Нажмите Enter для возврата в меню"
    }
}

# ============================================================================
# Главное меню
# ============================================================================

function Show-MainMenu {
    while ($true) {
        $configs = Show-ConfigMenu

        if ($configs.Count -eq 0) {
            Write-Host "Выберите действие: " -NoNewline -ForegroundColor Yellow
            $choice = Read-Host

            switch ($choice.ToUpper()) {
                'R' { continue }
                'Q' { return }
                default {
                    Write-Warning-Custom "Неверный выбор"
                    Start-Sleep -Seconds 1
                }
            }
        }
        else {
            Write-Host "Выберите конфигурацию (1-$($configs.Count)) или действие: " -NoNewline -ForegroundColor Yellow
            $choice = Read-Host

            switch ($choice.ToUpper()) {
                'R' { continue }
                'Q' { return }
                default {
                    $num = 0
                    if ([int]::TryParse($choice, [ref]$num)) {
                        if ($num -ge 1 -and $num -le $configs.Count) {
                            $selectedConfig = $configs[$num - 1].FullName
                            Connect-Vpn -ConfigPath $selectedConfig
                        }
                        else {
                            Write-Warning-Custom "Неверный номер конфигурации"
                            Start-Sleep -Seconds 1
                        }
                    }
                    else {
                        Write-Warning-Custom "Неверный ввод"
                        Start-Sleep -Seconds 1
                    }
                }
            }
        }
    }
}

# ============================================================================
# Точка входа
# ============================================================================

function Main {
    # Проверка прав администратора
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error-Custom "Требуются права администратора!"
        Write-Info "Запустите PowerShell от имени администратора"
        Read-Host "Нажмите Enter для выхода"
        exit 1
    }

    # Инициализация зависимостей
    if (-not (Initialize-Dependencies)) {
        Read-Host "`nНажмите Enter для выхода"
        exit 1
    }

    # Главное меню
    Show-MainMenu

    Clear-Screen
    Write-Success "До свидания!"
    Write-Host ""
}

# Запуск
Main
