param(
    [string]$ApiKey = "",
    [string]$NetworkId = "default-net",
    [string]$SocHost = "127.0.0.1",
    [int]$SocPort = 8080,
    [string]$SensorHost = "127.0.0.1",
    [int]$SensorPort = 5000,
    [switch]$NoBrowser
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
$socDir = Join-Path $root "soc_server"
$socApp = Join-Path $socDir "app.py"
$mainApp = Join-Path $root "main.py"

if (-not (Test-Path $venvPython)) {
    throw "Python venv not found at: $venvPython. Create it with: python -m venv .venv"
}

if (-not $ApiKey) {
    Write-Host "No API key supplied. Provision a sensor first:"
    Write-Host "  python .\soc_server\provision_sensor.py --db .\soc_server\soc.db --network $NetworkId --hostname demo-sensor"
    exit 1
}

$existing = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq "python.exe" -and $_.CommandLine -match "main.py|soc_server\\app.py"
}

if ($existing) {
    Write-Host "Stopping existing Python processes for the project..."
    $existing | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Start-Sleep -Seconds 2
}

Write-Host "Starting SOC server on http://${SocHost}:${SocPort}"
Start-Process -FilePath $venvPython -ArgumentList @($socApp, "--host", $SocHost, "--port", $SocPort) -WorkingDirectory $socDir -WindowStyle Minimized | Out-Null

Start-Sleep -Seconds 2

Write-Host "Starting demo sensor on http://${SensorHost}:${SensorPort}"
Start-Process -FilePath $venvPython -ArgumentList @($mainApp, "--demo", "--network-id", $NetworkId, "--soc-url", "http://${SocHost}:${SocPort}", "--soc-api-key", $ApiKey) -WorkingDirectory $root -WindowStyle Minimized | Out-Null

if (-not $NoBrowser) {
    Start-Process "http://${SensorHost}:${SensorPort}"
    Start-Process "http://${SocHost}:${SocPort}"
}

Write-Host "Services started."
Write-Host "SOC: http://${SocHost}:${SocPort}"
Write-Host "Dashboard: http://${SensorHost}:${SensorPort}"
