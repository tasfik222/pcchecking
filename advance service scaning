# =========================
#  Hybrid Analysis Service & Process Scanner
# =========================

# Replace with your real Hybrid Analysis API key
$HybridAnalysisApiKey = "5sgozkgf9b92256925v0b5yw1d3dce15qf0z1g4e0c847e3d7a7uoylv3bd5d0d1"
$OutputFile = "Suspicious_Services_Processes_Report.txt"
$ScanDelay = 15   # delay for API limits

# --- Get SHA256 of a file ---
function Get-FileHash256 {
    param([string]$FilePath)
    try {
        if (Test-Path $FilePath) {
            $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
            return $hash.Hash
        } else {
            Write-Warning "File not found: $FilePath"
            return $null
        }
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
        "User-Agent" = "Falcon Service Scanner 1.0"
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

# --- Get Services with Executable Paths ---
function Get-ServiceExecutables {
    $services = @()
    
    try {
        # Get Windows services
        $serviceList = Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, PathName, ProcessId
        
        foreach ($service in $serviceList) {
            if ($service.PathName) {
                # Extract executable path from PathName (might contain arguments)
                $path = $service.PathName
                
                # Remove quotes and extract executable
                if ($path -match '^"([^"]+)"') {
                    $exePath = $matches[1]
                } elseif ($path -match '^([^\s]+\.exe)') {
                    $exePath = $matches[1]
                } else {
                    $exePath = $path
                }
                
                # Only add if it's an executable
                if ($exePath -like "*.exe" -and (Test-Path $exePath)) {
                    $services += [PSCustomObject]@{
                        Type = "Service"
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        State = $service.State
                        ExecutablePath = $exePath
                        ProcessId = $service.ProcessId
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Error getting services: $($_.Exception.Message)"
    }
    
    return $services
}

# --- Get Running Processes ---
function Get-ProcessExecutables {
    $processes = @()
    
    try {
        $processList = Get-Process | Where-Object { $_.Path -and $_.Path -like "*.exe" }
        
        foreach ($process in $processList) {
            $processes += [PSCustomObject]@{
                Type = "Process"
                Name = $process.ProcessName
                DisplayName = $process.ProcessName
                State = "Running"
                ExecutablePath = $process.Path
                ProcessId = $process.Id
            }
        }
    }
    catch {
        Write-Warning "Error getting processes: $($_.Exception.Message)"
    }
    
    return $processes
}

# =========================
#     MAIN SCRIPT
# =========================

Write-Host "Scanning Services and Running Processes with Hybrid Analysis..." -ForegroundColor Green

# Get all executables from services and processes
Write-Host "Collecting services..." -ForegroundColor Yellow
$services = Get-ServiceExecutables

Write-Host "Collecting running processes..." -ForegroundColor Yellow
$processes = Get-ProcessExecutables

# Combine all items to scan
$allItems = $services + $processes

# Remove duplicates based on executable path
$uniqueItems = $allItems | Sort-Object ExecutablePath -Unique

Write-Host "Found $($services.Count) services and $($processes.Count) processes." -ForegroundColor Green
Write-Host "Total unique executables to scan: $($uniqueItems.Count)" -ForegroundColor Green

$suspiciousResults = @()
$scanCount = 0
$scannedHashes = @{}

# Processing loop
for ($i = 0; $i -lt $uniqueItems.Count; $i++) {

    $item = $uniqueItems[$i]
    $exePath = $item.ExecutablePath

    Write-Progress -Activity "Scanning Services & Processes" -Status "Processing: $(Split-Path $exePath -Leaf)" -PercentComplete (($i / $uniqueItems.Count) * 100)
    Write-Host "`nChecking: $exePath" -ForegroundColor Cyan
    Write-Host "  Type: $($item.Type) | Name: $($item.Name) | State: $($item.State)" -ForegroundColor Gray

    # Compute hash
    $fileHash = Get-FileHash256 -FilePath $exePath
    if (-not $fileHash) { 
        Write-Host "  Could not compute hash, skipping..." -ForegroundColor Yellow
        continue 
    }

    Write-Host "  SHA256: $($fileHash.Substring(0, 16))..." -ForegroundColor Gray

    # Skip if we already scanned this hash
    if ($scannedHashes.ContainsKey($fileHash)) {
        Write-Host "  Already scanned this file, using previous results..." -ForegroundColor Gray
        $haResult = $scannedHashes[$fileHash]
    } else {
        # Query Hybrid Analysis
        $haResult = Test-HybridAnalysis -FileHash $fileHash
        $scannedHashes[$fileHash] = $haResult
    }
    
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
                Type = $item.Type
                Name = $item.Name
                DisplayName = $item.DisplayName
                State = $item.State
                ProcessId = $item.ProcessId
                ExecutablePath = $exePath
                SHA256 = $fileHash
                ThreatLevel = $threatLevel
                ThreatScore = $threatScore
                MalwareFamilies = $malwareFamilies
                HALink = "https://www.hybrid-analysis.com/sample/$fileHash"
            }

            $suspiciousResults += $entry

            Write-Host "⚠️ SUSPICIOUS: $($item.Type) - $($item.Name)" -ForegroundColor Red
            Write-Host "   Threat Level: $threatLevel | Score: $threatScore" -ForegroundColor Red
        }
        else {
            Write-Host "✅ Clean: $($item.Type) - $($item.Name)" -ForegroundColor Green
        }
    }

    # obey API limits (Hybrid Analysis has strict limits)
    if ($scanCount -gt 0 -and $scanCount % 3 -eq 0) {
        Write-Host "Sleeping $ScanDelay seconds for API limits..." -ForegroundColor Yellow
        Start-Sleep -Seconds $ScanDelay
    }
}

Write-Progress -Activity "Scanning Services & Processes" -Completed

# --- Output Report ---
if ($suspiciousResults.Count -gt 0) {

    $report = @()
    $report += "SUSPICIOUS SERVICES & PROCESSES - HYBRID ANALYSIS REPORT"
    $report += "Generated: $(Get-Date)"
    $report += "Computer: $env:COMPUTERNAME"
    $report += "=" * 70
    $report += ""

    foreach ($entry in $suspiciousResults) {
        $report += "Type: $($entry.Type)"
        $report += "Name: $($entry.Name)"
        $report += "Display Name: $($entry.DisplayName)"
        $report += "State: $($entry.State)"
        $report += "Process ID: $($entry.ProcessId)"
        $report += "Executable Path: $($entry.ExecutablePath)"
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

    Write-Host "`n$($suspiciousResults.Count) suspicious items found!" -ForegroundColor Red
    Write-Host "Report saved to $OutputFile" -ForegroundColor Green

    # Display summary table
    $suspiciousResults | Format-Table -AutoSize -Property Type, Name, ThreatLevel, ThreatScore, ProcessId, ExecutablePath
}
else {
    Write-Host "`nNo suspicious services or processes found! ✅" -ForegroundColor Green
    "No suspicious services or processes found - Hybrid Analysis Scan - $(Get-Date)" | Out-File $OutputFile -Encoding UTF8
}

# Summary
Write-Host "`n" + "="*50 -ForegroundColor Cyan
Write-Host "SCAN SUMMARY" -ForegroundColor Cyan
Write-Host "Services scanned: $($services.Count)" -ForegroundColor White
Write-Host "Processes scanned: $($processes.Count)" -ForegroundColor White
Write-Host "Unique executables: $($uniqueItems.Count)" -ForegroundColor White
Write-Host "Hybrid Analysis queries: $scanCount" -ForegroundColor White
Write-Host "Suspicious items: $($suspiciousResults.Count)" -ForegroundColor $(if ($suspiciousResults.Count -gt 0) { "Red" } else { "Green" })
Write-Host "="*50 -ForegroundColor Cyan
