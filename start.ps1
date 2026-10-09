[CmdletBinding()]
param(
    [switch]$InstallFrontend,
    [switch]$InstallBackend
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$FrontendRoot = Join-Path $ProjectRoot 'frontend'
$BackendRoot = Join-Path $ProjectRoot 'backend'

function Fail([string]$Message) {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    exit 1
}

function Require-Command([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) { Fail "$Name was not found. $Hint" }
}

function Test-PortAvailable([int]$Port) {
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        return $true
    } catch [System.Net.Sockets.SocketException] {
        return $false
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

if (-not (Test-Path (Join-Path $FrontendRoot 'package.json'))) { Fail "Frontend directory was not found: $FrontendRoot" }
if (-not (Test-Path (Join-Path $BackendRoot 'run.py'))) { Fail "Unified backend entry was not found: $BackendRoot\run.py" }

Require-Command 'python' 'Install Python 3.10+ and add it to PATH.'
Require-Command 'npm' 'Install Node.js 18+ and add it to PATH.'
$pythonExe = (Get-Command python).Source
$npmExe = (Get-Command npm).Source

if ($InstallFrontend) {
    Write-Host '[INFO] Installing frontend dependencies...' -ForegroundColor Cyan
    Push-Location $FrontendRoot
    try { & $npmExe install } finally { Pop-Location }
}
if ($InstallBackend) {
    Write-Host '[INFO] Installing backend dependencies...' -ForegroundColor Cyan
    & $pythonExe -m pip install -r (Join-Path $BackendRoot 'requirements.txt')
}
if (-not (Test-Path (Join-Path $FrontendRoot 'node_modules'))) { Fail "Frontend dependencies are missing. Run: .\start.ps1 -InstallFrontend" }

$frontendPort = 5173
if (-not (Test-PortAvailable $frontendPort)) {
    $frontendPort = 5174
    Write-Host '[WARN] Port 5173 is already in use; frontend will use port 5174.' -ForegroundColor Yellow
}
if (-not (Test-PortAvailable $frontendPort)) { Fail "Frontend ports 5173 and 5174 are both in use." }

if (-not (Test-NetConnection -ComputerName '127.0.0.1' -Port 27017 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
    $mongoService = Get-Service -Name 'MongoDB' -ErrorAction SilentlyContinue
    if ($mongoService -and $mongoService.Status -ne 'Running') {
        try { Start-Service -Name 'MongoDB' -ErrorAction Stop; Start-Sleep -Seconds 2 } catch { Write-Host '[WARN] Could not start MongoDB service.' -ForegroundColor Yellow }
    }
    if (-not (Test-NetConnection -ComputerName '127.0.0.1' -Port 27017 -InformationLevel Quiet -WarningAction SilentlyContinue) -and (Get-Command docker -ErrorAction SilentlyContinue)) {
        $container = docker ps -a --filter 'name=^/spiderfort-mongodb$' --format '{{.Names}}' 2>$null
        if ($container -eq 'spiderfort-mongodb') { docker start spiderfort-mongodb | Out-Null }
        else { docker run -d --name spiderfort-mongodb -p 27017:27017 mongo:7 | Out-Null }
        Start-Sleep -Seconds 3
    }
}

if (-not (Test-NetConnection -ComputerName '127.0.0.1' -Port 27017 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
    Write-Host '[WARN] MongoDB is unavailable; the backend will start in degraded mode.' -ForegroundColor Yellow
}

$windowArgs = @('-NoExit', '-ExecutionPolicy', 'Bypass', '-Command')
Write-Host '[INFO] Starting unified backend on http://localhost:5000 ...' -ForegroundColor Green
Start-Process -WindowStyle Hidden -FilePath 'powershell.exe' -WorkingDirectory $BackendRoot -ArgumentList ($windowArgs + "& '$pythonExe' run.py")
Write-Host "[INFO] Starting frontend on http://localhost:$frontendPort ..." -ForegroundColor Green
Start-Process -WindowStyle Hidden -FilePath 'powershell.exe' -WorkingDirectory $FrontendRoot -ArgumentList ($windowArgs + "& '$npmExe' run dev -- --host 0.0.0.0 --port $frontendPort --strictPort")
Write-Host "Application launched. Open http://localhost:$frontendPort" -ForegroundColor Cyan
