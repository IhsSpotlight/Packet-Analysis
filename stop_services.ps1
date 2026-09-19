$root = Split-Path -Parent $MyInvocation.MyCommand.Path

Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq "python.exe" -and $_.CommandLine -match "main.py|soc_server\\app.py"
} | ForEach-Object {
    Write-Host "Stopping PID $($_.ProcessId)"
    Stop-Process -Id $_.ProcessId -Force
}

Write-Host "All sentinel python services stopped."
