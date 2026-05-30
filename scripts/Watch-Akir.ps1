param(
    [string]$Token = "",
    [int]$IntervalMinutes = 10,
    [string[]]$Repos = @("SHAdd0WTAka/Chain_of_Trust", "SHAdd0WTAka/AKIR-EDR")
)

if (-not $Token) {
    Write-Host "Usage: .\Watch-Akir.ps1 -Token ghp_yourToken" -ForegroundColor Yellow
    exit 1
}

$headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
$ErrorActionPreference = "Continue"

function Get-LatestRun($repo) {
    try {
        $runs = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/runs?per_page=3" -Headers $headers
        return $runs.workflow_runs[0]
    } catch { return $null }
}

function Get-BuildErrors($runId, $repo) {
    try {
        $jobs = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/runs/$runId/jobs" -Headers $headers
        $jobId = $jobs.jobs[0].id
        $logs = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/jobs/$jobId/logs" -Headers $headers -Method Get -ContentType "text/plain"
        $lines = $logs -split "`n"
        $errors = $lines | Select-String -Pattern "error C\d+|fatal error|LINK : fatal" | Select-Object -First 10
        return $errors -join "`n"
    } catch { return "Could not fetch logs" }
}

while ($true) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "`n===== WATCH $timestamp =====" -ForegroundColor Cyan

    foreach ($repo in $Repos) {
        $run = Get-LatestRun $repo
        if (-not $run) {
            Write-Host "[$repo] No runs found or API error" -ForegroundColor Gray
            continue
        }

        $icon = switch ($run.conclusion) {
            "success" { "🟢" }
            "failure" { "🔴" }
            "cancelled" { "⚪" }
            default { "🟡" }
        }

        $title = $run.display_title
        if ($title.Length -gt 60) { $title = $title.Substring(0, 57) + "..." }

        Write-Host "$icon [$repo] #$($run.run_number) $($run.conclusion) - $title" -ForegroundColor White

        if ($run.status -eq "completed" -and $run.conclusion -eq "failure") {
            $errors = Get-BuildErrors $run.id $repo
            if ($errors) {
                Write-Host "  Errors:" -ForegroundColor Red
                $errors -split "`n" | ForEach-Object {
                    if ($_.Trim()) { Write-Host "    $_" -ForegroundColor Red }
                }
            }
        }
    }

    Write-Host "`nNext check in $IntervalMinutes minutes. Press Ctrl+C to stop." -ForegroundColor DarkGray
    Start-Sleep -Seconds ($IntervalMinutes * 60)
}
