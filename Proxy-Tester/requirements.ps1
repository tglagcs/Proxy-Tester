# requirements.ps1
# Запуск: правой кнопкой -> Run with PowerShell или .\requirements.ps1

# Устанавливаем кодировку UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# Включаем строгий режим для отлова ошибок
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Цвета для вывода
$colors = @{
    Cyan = "Cyan"
    Green = "Green"
    Yellow = "Yellow"
    Red = "Red"
    White = "White"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

Write-ColorOutput "╔══════════════════════════════════════════════════════════════════╗" Cyan
Write-ColorOutput "║            🛡️  PROXY TESTER - УСТАНОВКА КОМПОНЕНТОВ              ║" Cyan
Write-ColorOutput "╚══════════════════════════════════════════════════════════════════╝" Cyan
Write-ColorOutput ""

# 1. Проверка Python
Write-ColorOutput "[1/6] Проверка Python..." Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-ColorOutput $pythonVersion Green
        Write-ColorOutput "✅ Python найден" Green
        
        # Проверка версии Python (нужен 3.7+)
        $versionMatch = [regex]::Match($pythonVersion, '\d+\.\d+')
        if ($versionMatch.Success) {
            $version = [version]$versionMatch.Value
            if ($version -lt [version]"3.7") {
                Write-ColorOutput "⚠️  Рекомендуется Python 3.7 или выше (у вас $version)" Yellow
            }
        }
    } else {
        throw "Python not found"
    }
} catch {
    Write-ColorOutput "❌ Python не найден!" Red
    Write-ColorOutput "   Скачайте и установите Python с https://www.python.org/downloads/" Yellow
    Write-ColorOutput "   Обязательно отметьте 'Add Python to PATH'" Yellow
    Write-ColorOutput ""
    Read-Host "Нажмите Enter для выхода"
    exit 1
}
Write-ColorOutput ""

# 2. Обновление pip
Write-ColorOutput "[2/6] Обновление pip..." Yellow
try {
    python -m pip install --upgrade pip -q
    Write-ColorOutput "✅ pip обновлен" Green
} catch {
    Write-ColorOutput "⚠️  Не удалось обновить pip, продолжаем..." Yellow
}
Write-ColorOutput ""

# 3. Установка Python библиотек (с правильными именами)
Write-ColorOutput "[3/6] Установка Python библиотек..." Yellow

# Создаем временный Python скрипт для проверки
$checkScript = @'
import importlib
import sys

# Соответствие: имя пакета -> имя для импорта
packages = {
    "pysocks": "socks",
    "colorama": "colorama",
    "tqdm": "tqdm", 
    "aiohttp": "aiohttp",
    "aiofiles": "aiofiles"
}
missing = []

for package_name, import_name in packages.items():
    try:
        module = importlib.import_module(import_name)
        version = getattr(module, "__version__", "unknown")
        print(f"OK:{package_name}:{version}")
    except ImportError:
        print(f"MISSING:{package_name}")
        missing.append(package_name)

if missing:
    print(f"TOINSTALL:{','.join(missing)}")
else:
    print("ALL_OK")
'@

# Сохраняем скрипт во временный файл
$tempScript = [System.IO.Path]::GetTempFileName() + ".py"
$checkScript | Out-File -FilePath $tempScript -Encoding UTF8

# Запускаем проверку
$checkResult = python $tempScript 2>&1

$packagesToInstall = @()
foreach ($line in $checkResult) {
    if ($line -match "^OK:(.+):(.+)$") {
        $pkg = $matches[1]
        $ver = $matches[2]
        Write-ColorOutput "    ✅ $pkg $ver (уже установлен)" Green
    }
    elseif ($line -match "^MISSING:(.+)$") {
        $pkg = $matches[1]
        Write-ColorOutput "    ⚠️  $pkg не найден, будет установлен" Yellow
        $packagesToInstall += $pkg
    }
}

if ($packagesToInstall.Count -gt 0) {
    Write-ColorOutput "    📦 Установка $($packagesToInstall.Count) пакетов..." Yellow
    foreach ($package in $packagesToInstall) {
        Write-ColorOutput "        Установка $package..." Yellow
        pip install $package -q 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "        ✅ $package установлен" Green
        } else {
            Write-ColorOutput "        ❌ Ошибка установки $package" Red
        }
    }
} else {
    Write-ColorOutput "    ✅ Все библиотеки уже установлены" Green
}

# Удаляем временный файл
Remove-Item $tempScript -Force -ErrorAction SilentlyContinue
Write-ColorOutput ""

# 4. Проверка/Установка Scoop
Write-ColorOutput "[4/6] Проверка Scoop..." Yellow
$scoopExists = Get-Command scoop -ErrorAction SilentlyContinue
if (-not $scoopExists) {
    Write-ColorOutput "⚠️  Scoop не найден, устанавливаем..." Yellow
    
    # Проверка PowerShell версии
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-ColorOutput "❌ Требуется PowerShell 5.0 или выше (у вас $psVersion)" Red
        Write-ColorOutput "   Обновите PowerShell: https://aka.ms/pscore6" Yellow
        Read-Host "Нажмите Enter для выхода"
        exit 1
    }
    
    # Установка Scoop
    Write-ColorOutput "    Установка Scoop (может занять несколько минут)..." Yellow
    try {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Invoke-RestMethod -Uri "https://get.scoop.sh" | Invoke-Expression
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Scoop установлен" Green
            # Обновляем PATH
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","User") + ";" + [System.Environment]::GetEnvironmentVariable("Path","Machine")
        } else {
            throw "Scoop installation failed"
        }
    } catch {
        Write-ColorOutput "❌ Ошибка установки Scoop: $_" Red
        Write-ColorOutput "   Альтернативный способ: установите Xray вручную" Yellow
        Write-ColorOutput "   https://github.com/XTLS/Xray-core/releases" Yellow
        Read-Host "Нажмите Enter для продолжения или Ctrl+C для выхода"
    }
} else {
    Write-ColorOutput "✅ Scoop уже установлен" Green
}
Write-ColorOutput ""

# 5. Установка Xray-core (исправленная версия)
Write-ColorOutput "[5/6] Установка Xray-core..." Yellow
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-ColorOutput "    Обновление Scoop..." Yellow
    scoop update 2>&1 | Out-Null  # Убираем -q
    
    Write-ColorOutput "    Проверка Xray-core..." Yellow
    $xrayInstalled = scoop list | Select-String "xray"
    
    if (-not $xrayInstalled) {
        Write-ColorOutput "    Установка Xray-core..." Yellow
        scoop install xray 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "✅ Xray-core установлен" Green
        } else {
            Write-ColorOutput "⚠️  Возможно, Xray-core уже установлен, проверяем..." Yellow
        }
    } else {
        Write-ColorOutput "✅ Xray-core уже установлен" Green
    }
    
    # Проверяем, что xray работает
    $xrayPath = (Get-Command xray -ErrorAction SilentlyContinue).Source
    if ($xrayPath) {
        Write-ColorOutput "   📍 Xray путь: $xrayPath" White
        $xrayVer = & xray -version 2>&1 | Select-Object -First 1
        Write-ColorOutput "   📍 Xray версия: $xrayVer" White
    } else {
        Write-ColorOutput "   ⚠️  Xray не найден в PATH, перезапустите терминал" Yellow
    }
} else {
    Write-ColorOutput "⚠️  Scoop не установлен, пропускаем Xray-core" Yellow
    Write-ColorOutput "   Установите Xray вручную из https://github.com/XTLS/Xray-core/releases" Yellow
}
Write-ColorOutput ""

# 6. Создание примера конфигурации
Write-ColorOutput "[6/6] Создание примера конфигурации..." Yellow
if (-not (Test-Path "servers.txt")) {
    $exampleConfig = @"
# СПИСОК СЕРВЕРОВ ДЛЯ ПРОВЕРКИ
# Поддерживаются: vless://, vmess://, trojan://, ss://
# 
# Форматы ссылок:
# 
# VLESS: vless://UUID@host:port?encryption=none&security=tls&sni=domain&type=ws&host=domain&path=/path#Name
# 
# VMESS: vmess://base64(JSON)
# 
# Trojan: trojan://PASSWORD@host:port?security=tls&sni=domain&type=ws&host=domain&path=/path#Name
# 
# Shadowsocks: ss://BASE64(method:password)@host:port#Name

# Вставьте свои серверы ниже (каждый на новой строке):

"@
    $exampleConfig | Out-File -FilePath "servers.txt" -Encoding UTF8
    Write-ColorOutput "✅ Создан файл servers.txt с примером" Green
    Write-ColorOutput "   📝 Отредактируйте его, добавив свои прокси" Yellow
} else {
    Write-ColorOutput "✅ Файл servers.txt уже существует" Green
}
Write-ColorOutput ""

# Финальная проверка
Write-ColorOutput "╔══════════════════════════════════════════════════════════════════╗" Cyan
Write-ColorOutput "║              ✅ УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО!                    ║" Cyan
Write-ColorOutput "╚══════════════════════════════════════════════════════════════════╝" Cyan
Write-ColorOutput ""

Write-ColorOutput "📦 Установленные компоненты:" Yellow
Write-ColorOutput "   • Python $pythonVersion" White
Write-ColorOutput "   • Библиотеки: pysocks, colorama, tqdm, aiohttp" White

if (Get-Command xray -ErrorAction SilentlyContinue) {
    $xrayVer = xray -version 2>&1 | Select-Object -First 1
    Write-ColorOutput "   • Xray-core: $xrayVer" White
}

Write-ColorOutput ""
Write-ColorOutput "🚀 Запуск тестера:" Yellow
Write-ColorOutput "   python proxy-tester.py" White
Write-ColorOutput ""
Write-ColorOutput "📝 Заметки:" Yellow
Write-ColorOutput "   • Добавить прокси: отредактируйте servers.txt" White
Write-ColorOutput "   • Запустить тест: python proxy-tester.py" White
Write-ColorOutput "   • Открыть отчет: report_*.html (создается автоматически)" White
Write-ColorOutput ""

# Создание run.bat для быстрого запуска
$runBat = @'
@echo off
chcp 65001 > nul
echo Starting Proxy Tester...
python proxy-tester.py
pause
'@

if (-not (Test-Path "run.bat")) {
    $runBat | Out-File -FilePath "run.bat" -Encoding ASCII
    Write-ColorOutput "📁 Создан run.bat для быстрого запуска" Green
}

Write-ColorOutput ""
Read-Host "Нажмите Enter для выхода"