# LLP Client Build Script
# Simple version without Unicode characters

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LLP Client - Build Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check .NET SDK
Write-Host ">> Checking .NET SDK..." -ForegroundColor Green
try {
    $dotnetVersion = dotnet --version
    Write-Host "[OK] .NET SDK installed: $dotnetVersion" -ForegroundColor Green
}
catch {
    Write-Host "[ERROR] .NET SDK not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Install .NET 8 SDK:" -ForegroundColor Yellow
    Write-Host "  winget install Microsoft.DotNet.SDK.8" -ForegroundColor Yellow
    Write-Host "  or download: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
    exit 1
}

# Change to project directory
Set-Location $PSScriptRoot\LLPClient

Write-Host ""
Write-Host ">> Restoring dependencies..." -ForegroundColor Green
dotnet restore

Write-Host ""
Write-Host ">> Building Release version..." -ForegroundColor Green
dotnet publish -c Release -r win-x64 --self-contained

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[OK] Build completed successfully!" -ForegroundColor Green
    Write-Host ""

    $outputPath = "bin\Release\net8.0\win-x64\publish\LLPClient.exe"
    $fileInfo = Get-Item $outputPath
    $sizeMB = [math]::Round($fileInfo.Length / 1MB, 2)

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Binary: $outputPath" -ForegroundColor White
    Write-Host "Size: $sizeMB MB" -ForegroundColor White
    Write-Host ""
    Write-Host "Installation:" -ForegroundColor Yellow
    Write-Host "  1. Create folder: mkdir C:\LLP" -ForegroundColor White
    Write-Host "  2. Copy: Copy-Item '$outputPath' C:\LLP\" -ForegroundColor White
    Write-Host "  3. Create configs: mkdir C:\LLP\configs" -ForegroundColor White
    Write-Host "  4. Run: cd C:\LLP; .\LLPClient.exe" -ForegroundColor White
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
}
else {
    Write-Host ""
    Write-Host "[ERROR] Build failed!" -ForegroundColor Red
    exit 1
}
