param(
    [string]$Token = "",
    [int]$IntervalMinutes = 10
)

if (-not $Token) {
    Write-Host "Usage: .\Setup-RHALF-Cron.ps1 -Token ghp_yourToken" -ForegroundColor Yellow
    exit 1
}

$taskName = "RHALF-Improve-Agent"
$scriptPath = "$PSScriptRoot\RHALF-Improve.ps1"
$logPath = "$env:USERPROFILE\RHALF-Logs"

# Create log directory
if (-not (Test-Path $logPath)) { New-Item -ItemType Directory -Path $logPath -Force | Out-Null }

# Register the Task Scheduler job
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NoLogo -ExecutionPolicy Bypass -File `"$scriptPath`" -Token `"$Token`" -LogDir `"$logPath`""

$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 365) `
    -At (Get-Date).AddMinutes(1) `
    -Once

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
    Write-Host "[RHALF] Task '$taskName' registered - runs every $IntervalMinutes minutes" -ForegroundColor Green
    Write-Host "[RHALF] Script: $scriptPath" -ForegroundColor Cyan
    Write-Host "[RHALF] Logs: $logPath" -ForegroundColor Cyan
} catch {
    Write-Host "[RHALF] Failed to register task: $_" -ForegroundColor Red
    Write-Host "[RHALF] Try running as Administrator" -ForegroundColor Yellow
}

# Test the task
Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Format-List TaskName, State, Triggers, Actions

Write-Host "`nTo remove later: Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false" -ForegroundColor Gray
