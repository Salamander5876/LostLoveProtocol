#!/usr/bin/env pwsh
# Скрипт сборки LLP Client (C#)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   LLP Client - Build Script               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Проверка .NET SDK
Write-Host "▸ Проверка .NET SDK..." -ForegroundColor Green
try {
    $dotnetVersion = dotnet --version
    Write-Host "✓ .NET SDK установлен: $dotnetVersion" -ForegroundColor Green
}
catch {
    Write-Host "✗ .NET SDK не найден!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Установите .NET 8 SDK:" -ForegroundColor Yellow
    Write-Host "  winget install Microsoft.DotNet.SDK.8" -ForegroundColor Yellow
    Write-Host "  или скачайте: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
    exit 1
}

# Переход в папку проекта
Set-Location $PSScriptRoot\LLPClient

Write-Host ""
Write-Host "▸ Восстановление зависимостей..." -ForegroundColor Green
dotnet restore

Write-Host ""
Write-Host "▸ Сборка Release версии..." -ForegroundColor Green
dotnet publish -c Release -r win-x64 --self-contained

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✓ Сборка завершена успешно!" -ForegroundColor Green
    Write-Host ""

    $outputPath = "bin\Release\net8.0\win-x64\publish\LLPClient.exe"
    $fileInfo = Get-Item $outputPath
    $sizeMB = [math]::Round($fileInfo.Length / 1MB, 2)

    Write-Host "════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📦 Бинарник: $outputPath" -ForegroundColor White
    Write-Host "📊 Размер: $sizeMB MB" -ForegroundColor White
    Write-Host ""
    Write-Host "Установка:" -ForegroundColor Yellow
    Write-Host "  1. Создайте папку: mkdir C:\LLP" -ForegroundColor White
    Write-Host "  2. Скопируйте: Copy-Item '$outputPath' C:\LLP\" -ForegroundColor White
    Write-Host "  3. Создайте configs: mkdir C:\LLP\configs" -ForegroundColor White
    Write-Host "  4. Запустите: cd C:\LLP; .\LLPClient.exe" -ForegroundColor White
    Write-Host ""
    Write-Host "════════════════════════════════════════════" -ForegroundColor Cyan
}
else {
    Write-Host ""
    Write-Host "✗ Ошибка сборки!" -ForegroundColor Red
    exit 1
}
