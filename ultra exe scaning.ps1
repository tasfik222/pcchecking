# =========================
#  Hybrid Analysis Scanner
# =========================

# Replace with your real Hybrid Analysis API key
$HybridAnalysisApiKey = "5sgozkgf9b92256925v0b5yw1d3dce15qf0z1g4e0c847e3d7a7uoylv3bd5d0d1"
$OutputFile = "SuspiciousEXEs_Report.txt"
$ScanDelay = 15   # delay for API limits

# --- Get SHA256 of a file ---
function Get-FileHash256 {
    param([string]$FilePath)
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    }
    catch {
        Write-Warning "Cannot hash file: $FilePath - $($_.Exception.Message)"
        return $null
    }
}

# --- Hybrid Analysis Query ---
function Test-HybridAnalysis {
    param([string]$FileHash)

    if (-not $FileHash) { return $null }

    $headers = @{
        "api-key" = $HybridAnalysisApiKey
        "User-Agent" = "Falcon Hash Scanner 1.0"
        "accept" = "application/json"
    }

    try {
        $uri = "https://www.hybrid-analysis.com/api/v2/overview/$FileHash"
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction Stop
        return $response
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            Write-Host "Not found on Hybrid Analysis: $FileHash" -ForegroundColor Yellow
            return "Not Found"
        }
        elseif ($_.Exception.Response.StatusCode -eq 429) {
            Write-Warning "Rate limit exceeded. Waiting 60 seconds..."
            Start-Sleep -Seconds 60
            return $null
        }
        Write-Warning "Hybrid Analysis API error: $($_.Exception.Message)"
        return $null
    }
}

# --- Parse Hybrid Analysis Results ---
function Get-HybridAnalysisThreatLevel {
    param($HAResult)
    
    if (-not $HAResult -or -not $HAResult.verdict) { return "Unknown" }
    
    return $HAResult.verdict
}

function Get-HybridAnalysisScore {
    param($HAResult)
    
    if (-not $HAResult -or -not $HAResult.threat_score) { return $null }
    
    return $HAResult.threat_score
}

function Get-HybridAnalysisMalwareFamilies {
    param($HAResult)
    
    if (-not $HAResult -or -not $HAResult.malware_families) { return @() }
    
    return $HAResult.malware_families -join ", "
}

# =========================
#     MAIN SCRIPT
# =========================

Write-Host "Scanning running EXE files with Hybrid Analysis..." -ForegroundColor Green

# Get unique EXE file paths of running processes
$executables = Get-Process | ForEach-Object {
    try { $_.Path } catch { $null }
} | Where-Object { $_ -and $_ -like "*.exe" } | Sort-Object -Unique

Write-Host "Found $($executables.Count) running EXE files." -ForegroundColor Green

$suspiciousResults = @()
$scanCount = 0

# Processing loop
for ($i = 0; $i -lt $executables.Count; $i++) {

    $exePath = $executables[$i]

    Write-Progress -Activity "Scanning EXEs with Hybrid Analysis" -Status "Processing: $(Split-Path $exePath -Leaf)" -PercentComplete (($i / $executables.Count) * 100)
    Write-Host "`nChecking: $exePath" -ForegroundColor Cyan

    # Compute hash
    $fileHash = Get-FileHash256 -FilePath $exePath
    if (-not $fileHash) { 
        Write-Host "  Could not compute hash, skipping..." -ForegroundColor Yellow
        continue 
    }

    Write-Host "  SHA256: $($fileHash.Substring(0, 16))..." -ForegroundColor Gray

    # Query Hybrid Analysis
    $haResult = Test-HybridAnalysis -FileHash $fileHash
    
    if ($haResult -eq "Not Found") { 
        Write-Host "  Not in Hybrid Analysis database" -ForegroundColor Yellow
        continue 
    }
    elseif ($haResult) {
        $scanCount++
        $threatLevel = Get-HybridAnalysisThreatLevel -HAResult $haResult
        $threatScore = Get-HybridAnalysisScore -HAResult $haResult
        $malwareFamilies = Get-HybridAnalysisMalwareFamilies -HAResult $haResult
        
        Write-Host "  Threat Level: $threatLevel" -ForegroundColor White
        Write-Host "  Threat Score: $threatScore" -ForegroundColor White
        
        if ($malwareFamilies) {
            Write-Host "  Malware Families: $malwareFamilies" -ForegroundColor White
        }

        # Check if suspicious or malicious
        if ($threatLevel -eq "malicious" -or $threatLevel -eq "suspicious" -or $threatScore -gt 50) {
            $entry = [PSCustomObject]@{
                EXEPath = $exePath
                SHA256 = $fileHash
                ThreatLevel = $threatLevel
                ThreatScore = $threatScore
                MalwareFamilies = $malwareFamilies
                HALink = "https://www.hybrid-analysis.com/sample/$fileHash"
            }

            $suspiciousResults += $entry

            Write-Host "⚠️ SUSPICIOUS: $exePath" -ForegroundColor Red
            Write-Host "   Threat Level: $threatLevel | Score: $threatScore" -ForegroundColor Red
        }
        else {
            Write-Host "✅ Clean: $exePath" -ForegroundColor Green
        }
    }

    # obey API limits (Hybrid Analysis has strict limits)
    if ($scanCount -gt 0 -and $scanCount % 3 -eq 0) {
        Write-Host "Sleeping $ScanDelay seconds for API limits..." -ForegroundColor Yellow
        Start-Sleep -Seconds $ScanDelay
    }
}

Write-Progress -Activity "Scanning EXEs" -Completed

# --- Output Report ---
if ($suspiciousResults.Count -gt 0) {

    $report = @()
    $report += "SUSPICIOUS EXE FILES - HYBRID ANALYSIS REPORT"
    $report += "Generated: $(Get-Date)"
    $report += "=" * 70
    $report += ""

    foreach ($entry in $suspiciousResults) {
        $report += "EXE Path: $($entry.EXEPath)"
        $report += "SHA256: $($entry.SHA256)"
        $report += "Threat Level: $($entry.ThreatLevel)"
        $report += "Threat Score: $($entry.ThreatScore)"
        if ($entry.MalwareFamilies) {
            $report += "Malware Families: $($entry.MalwareFamilies)"
        }
        $report += "Hybrid Analysis: $($entry.HALink)"
        $report += "-" * 50
    }

    $report | Out-File $OutputFile -Encoding UTF8

    Write-Host "`n$($suspiciousResults.Count) suspicious EXEs found!" -ForegroundColor Red
    Write-Host "Report saved to $OutputFile" -ForegroundColor Green

    $suspiciousResults | Format-Table -AutoSize -Property EXEPath, ThreatLevel, ThreatScore, MalwareFamilies
}
else {
    Write-Host "`nNo suspicious EXE files found! ✅" -ForegroundColor Green
    "No suspicious EXEs found - Hybrid Analysis Scan - $(Get-Date)" | Out-File $OutputFile -Encoding UTF8
}

Write-Host "`nScan completed. Scanned $scanCount files with Hybrid Analysis." -ForegroundColor Cyan
