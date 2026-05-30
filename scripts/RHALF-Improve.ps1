<#
.SYNOPSIS
  RHALF Autonomous Improvement Engine
  R - Research & Recon    (scan repos, CI, issues)
  H - Hypothesize & Harden (identify fixes, security)
  A - Act & Apply          (push changes)
  L - Learn & Log          (record outcomes)
  F - Feedback & Forward   (trigger next cycle)
#>

param(
    [string]$Token = "",
    [string]$LogDir = "$env:USERPROFILE\RHALF-Logs"
)

if (-not $Token) { Write-Host "[RHALF] ERROR: No token"; exit 1 }

$headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = "$LogDir\cycle-$timestamp.log"
$repos = @("SHAdd0WTAka/Chain_of_Trust", "SHAdd0WTAka/AKIR-EDR")

function Log { param([string]$Msg) $line = "[$(Get-Date -Format HH:mm:ss)] $Msg"; Write-Host $line; Add-Content -Path $logFile -Value $line }

Log "============================================"
Log "RHALF Cycle Started"
Log "============================================"

# ---- R: Research & Recon ----
Log "[R] Research phase - scanning all repos"
$results = @()
foreach ($repo in $repos) {
    try {
        $runs = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/runs?per_page=3" -Headers $headers -ErrorAction Stop
        $latest = $runs.workflow_runs[0]
        $result = @{
            repo = $repo
            runNumber = $latest.run_number
            status = $latest.status
            conclusion = $latest.conclusion
            title = $latest.display_title
            url = $latest.html_url
        }
        $results += $result

        # Check for recent failures
        $failed = $runs.workflow_runs | Where-Object { $_.status -eq "completed" -and $_.conclusion -eq "failure" } | Select-Object -First 1
        if ($failed) {
            Log "[R] FAILURE in $repo - run #$($failed.run_number)"
            # Try to get failure logs
            try {
                $runId = $failed.id
                $jobsResponse = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/runs/$runId/jobs" -Headers $headers
                if ($jobsResponse.jobs.Count -gt 0) {
                    $jobId = $jobsResponse.jobs[0].id
                    $logText = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/jobs/$jobId/logs" -Headers $headers
                    $errors = $logText -split "`n" | Select-String -Pattern "error|Error|ERROR|fatal|FAILED|LINK" | Select-Object -First 20
                    Log "[R] Error lines:"
                    foreach ($e in $errors) { Log "[R]   $e" }
                }
            } catch { Log "[R] Could not fetch logs: $_" }
        } else {
            Log "[R] $repo - run #$($latest.run_number): $($latest.conclusion) - OK"
        }
    } catch {
        Log "[R] Error scanning $repo : $_"
    }
}

# ---- H: Hypothesize & Harden ----
Log "[H] Hypothesis phase - analyzing improvement opportunities"
$improvements = @()

foreach ($result in $results) {
    $repo = $result.repo
    $run = $result

    if ($run.conclusion -eq "failure") {
        $improvements += @{ repo = $repo; type = "fix-ci"; priority = 1; desc = "CI failure in run #$($run.runNumber)" }
    }

    # Check for security hardening opportunities
    if ($repo -like "*Chain*") {
        $improvements += @{ repo = $repo; type = "harden"; priority = 2; desc = "Review secret scanning / branch protection" }
        $improvements += @{ repo = $repo; type = "audit-deps"; priority = 3; desc = "Audit dependency versions" }
    }
    if ($repo -like "*AKIR-EDR*") {
        $improvements += @{ repo = $repo; type = "harden-sign"; priority = 2; desc = "Add binary signing step" }
    }
}

# Sort by priority
$improvements = $improvements | Sort-Object priority
Log "[H] Identified $($improvements.Count) improvements"

# ---- A: Act & Apply ----
Log "[A] Action phase - applying improvements"
foreach ($imp in $improvements) {
    Log "[A] Action: [$($imp.priority)] $($imp.repo) - $($imp.desc)"

    switch ($imp.type) {
        "fix-ci" {
            Log "[A] CI failure detected - requires human review for complex fix"
        }
        "harden" {
            Log "[A] Checking branch protection settings..."
            try {
                $repo = $imp.repo
                $branch = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/branches/main" -Headers $headers
                $protection = $branch.protection_url
                Log "[A] Branch: main, Protection URL: $protection"
            } catch { Log "[A] Error: $_" }
        }
        "audit-deps" {
            Log "[A] Checking for dependency files..."
            try {
                $repo = $imp.repo
                $files = @("vcpkg.json", "CMakeLists.txt", "package.json")
                foreach ($f in $files) {
                    try {
                        $fileCheck = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/contents/$f" -Headers $headers -ErrorAction SilentlyContinue
                        if ($fileCheck) { Log "[A]   Found: $f" }
                    } catch { Log "[A]   Not found: $f" }
                }
            } catch { Log "[A] Error: $_" }
        }
        default { Log "[A] Unknown action type: $($imp.type)" }
    }
}

# ---- L: Learn & Log ----
Log "[L] Learn phase - recording insights"
$cycleResults = $results | ForEach-Object { "$($_.repo): #$($_.runNumber) $($_.conclusion)" }
Log "[L] Cycle summary: $($cycleResults -join ' | ')"
Log "[L] Total repos: $($results.Count) | Green: $(($results | Where-Object { $_.conclusion -eq "success" }).Count) | Failures: $(($results | Where-Object { $_.conclusion -eq "failure" }).Count)"

# ---- F: Feedback & Forward ----
Log "[F] Feedback phase - planning next cycle"
Log "[F] Next cycle in 10 minutes"
Log "============================================"
Log "RHALF Cycle Complete"
Log "============================================"

# Output summary in machine-readable format for the AI
Write-Output "RHALF_SUMMARY: repos=$($results.Count) green=$(($results | Where-Object { $_.conclusion -eq "success" }).Count) failed=$(($results | Where-Object { $_.conclusion -eq "failure" }).Count) improvements=$($improvements.Count)"
