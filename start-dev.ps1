﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿# ContextForge 开发服务器启动脚本 (Windows PowerShell)
# 用法:
#   .\start-dev.ps1              # 默认端口 8004
#   .\start-dev.ps1 -Port 8001   # 指定端口

param(
    [int]$Port = 8004
)

# 修复 PowerShell 5 中文乱码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 > $null

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ContextForge 开发服务器启动" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. 检查 .env
Write-Host "[1/4] 检查 .env 配置..." -ForegroundColor Yellow
if (-not (Test-Path "$ProjectRoot\.env")) {
    Write-Host "  .env 不存在，正在从 .env.example 复制..." -ForegroundColor Gray
    Copy-Item "$ProjectRoot\.env.example" "$ProjectRoot\.env"
    Write-Host "  请编辑 .env 并设置 JWT_SECRET_KEY 和 AUTH_ENCRYPTION_SECRET" -ForegroundColor Red
    exit 1
}
Write-Host "  .env  OK" -ForegroundColor Green

# 2. 检查虚拟环境
Write-Host "[2/4] 检查 Python 虚拟环境..." -ForegroundColor Yellow
$VenvPython = "$ProjectRoot\.venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "  .venv 不存在，正在创建..." -ForegroundColor Gray
    Push-Location $ProjectRoot
    uv venv .venv
    Pop-Location
    Write-Host "  正在安装依赖..." -ForegroundColor Gray
    Push-Location $ProjectRoot
    uv pip install ".[plugins]"
    Pop-Location
}
Write-Host "  .venv  OK" -ForegroundColor Green

# 3. 检查端口占用
Write-Host "[3/4] 检查端口 $Port..." -ForegroundColor Yellow
$portInUse = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($portInUse) {
    $procId = $portInUse.OwningProcess
    Write-Host "  端口 $Port 被进程 $procId 占用，尝试自动终止..." -ForegroundColor Yellow
    try {
        Stop-Process -Id $procId -Force -ErrorAction Stop
        Write-Host "  已终止进程 $procId" -ForegroundColor Green
        Start-Sleep -Seconds 2
    } catch {
        Write-Host "  无法终止进程 $procId（可能是僵尸端口或权限不足）" -ForegroundColor Red
        Write-Host "  请使用 -Port 参数换一个端口，例如: .\start-dev.ps1 -Port 8005" -ForegroundColor Yellow
        exit 1
    }
    $stillInUse = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($stillInUse) {
        Write-Host "  端口 $Port 仍被占用（僵尸端口，需等待内核释放）" -ForegroundColor Red
        Write-Host "  请使用 -Port 参数换一个端口，例如: .\start-dev.ps1 -Port 8005" -ForegroundColor Yellow
        exit 1
    }
}
Write-Host "  端口 $Port  空闲" -ForegroundColor Green

# 4. 启动开发服务器
Write-Host "[4/4] 启动开发服务器..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  地址: http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "  文档: http://127.0.0.1:$Port/docs" -ForegroundColor Cyan
Write-Host "  管理: http://127.0.0.1:$Port/admin" -ForegroundColor Cyan
Write-Host "  按 Ctrl+C 停止" -ForegroundColor Gray
Write-Host ""

$env:TEMPLATES_AUTO_RELOAD = "true"

Push-Location $ProjectRoot
try {
    & "$ProjectRoot\.venv\Scripts\uvicorn.exe" `
        mcpgateway.main:app `
        --host 0.0.0.0 `
        --port $Port `
        --reload `
        --reload-dir mcpgateway
} finally {
    Pop-Location
    Write-Host ""
    Write-Host "服务器已停止" -ForegroundColor Yellow
}
