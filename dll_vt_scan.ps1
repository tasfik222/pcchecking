# ===========================================================
# VirusTotal Hash Scanner - Full PC DLL Scan
# Works on PowerShell 5.x and 7.x
# ===========================================================

$ApiKey = "fbea53db4a635688bccdc8b4241858cc5bb3ea55f6d2b91254b1c98f2d302191"
$LogFile = "C:\VirusTotal_Scan_Log.txt"

# Create log header
"=== VirusTotal Hash Scan Started at $(Get-Date) ===" | Out-File $LogFile
Write-Host "Starting scan... Log file: $LogFile" -ForegroundColor Yellow

# Get all EXE files from C: drive (with better error handling)
try {
    $ExeFiles = Get-ChildItem -Path C:\ -Filter *.dll -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 50
    Write-Host "Found $($ExeFiles.Count) EXE files to scan" -ForegroundColor Green
} catch {
    $errorMsg = "ERROR enumerating files: $_"
    $errorMsg | Out-File $LogFile -Append
    Write-Host $errorMsg -ForegroundColor Red
    exit 1
}

$scannedCount = 0
$errorCount = 0

foreach ($File in $ExeFiles) {
    $scannedCount++
    Write-Progress -Activity "Scanning Files" -Status "Processing $($File.Name)" -PercentComplete (($scannedCount / $ExeFiles.Count) * 100)

    try {
        Write-Host "`nChecking [$scannedCount/$($ExeFiles.Count)]: $($File.Name)" -ForegroundColor Cyan

        # Verify file exists and is accessible
        if (-not (Test-Path $File.FullName)) {
            "[$(Get-Date)] WARNING: File no longer exists - $($File.FullName)" | Out-File $LogFile -Append
            continue
        }

        # Calculate SHA256 hash
        $Sha256 = Get-FileHash -Path $File.FullName -Algorithm SHA256 -ErrorAction Stop | Select-Object -ExpandProperty Hash
        
        if (-not $Sha256) {
            "[$(Get-Date)] ERROR: Could not calculate hash for $($File.FullName)" | Out-File $LogFile -Append
            $errorCount++
            continue
        }

        Write-Host "  Hash: $($Sha256.Substring(0, 16))..." -ForegroundColor Gray

        # VirusTotal API URL
        $VTurl = "https://www.virustotal.com/api/v3/files/$Sha256"

        # Send request to VirusTotal with timeout
        $Response = Invoke-RestMethod -Method Get -Uri $VTurl -Headers @{
            "x-apikey" = $ApiKey
        } -TimeoutSec 30 -ErrorAction Stop

        # Extract detection info
        $Stats = $Response.data.attributes.last_analysis_stats
        $Malicious = $Stats.malicious
        $Suspicious = $Stats.suspicious
        $Undetected = $Stats.undetected
        $TotalEngines = $Malicious + $Suspicious + $Undetected

        # Color code based on threat level
        if ($Malicious -gt 0) {
            $Color = "Red"
            $ThreatLevel = "MALICIOUS"
        } elseif ($Suspicious -gt 0) {
            $Color = "Yellow" 
            $ThreatLevel = "SUSPICIOUS"
        } else {
            $Color = "Green"
            $ThreatLevel = "CLEAN"
        }

        $LogText = "[$(Get-Date)] $ThreatLevel - $($File.FullName)`nSHA256: $Sha256`nDetections: $Malicious malicious, $Suspicious suspicious, $Undetected undetected (out of $TotalEngines engines)`n---"
        $LogText | Out-File $LogFile -Append
        
        Write-Host "  Result: $Malicious malicious, $Suspicious suspicious - $ThreatLevel" -ForegroundColor $Color

    } catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode -eq 404) {
            # File not found in VirusTotal database
            $LogText = "[$(Get-Date)] UNKNOWN - $($File.FullName)`nSHA256: $Sha256`nStatus: File not found in VirusTotal database`n---"
            $LogText | Out-File $LogFile -Append
            Write-Host "  Result: Not found in VirusTotal database" -ForegroundColor Gray
        } elseif ($_.Exception.Response.StatusCode -eq 429) {
            # Rate limit exceeded
            $errorMsg = "[$(Get-Date)] ERROR: VirusTotal API rate limit exceeded. Please wait and try again later."
            $errorMsg | Out-File $LogFile -Append
            Write-Host $errorMsg -ForegroundColor Red
            break
        } else {
            # Other web errors
            "[$(Get-Date)] ERROR scanning $($File.FullName): $($_.Exception.Message)" | Out-File $LogFile -Append
            Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
            $errorCount++
        }
    } catch {
        # General errors
        $errorMsg = "[$(Get-Date)] ERROR processing $($File.FullName): $($_.Exception.Message)"
        $errorMsg | Out-File $LogFile -Append
        Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }

    # Rate limiting - increased delay for public API
    Write-Host "  Waiting 15 seconds for rate limit..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 15
}

# Final summary
$summary = @"
=== Scan Completed at $(Get-Date) ===
Total files scanned: $scannedCount
Successful scans: $(($scannedCount - $errorCount))
Errors encountered: $errorCount
Log file: $LogFile
"@

$summary | Out-File $LogFile -Append
Write-Host "`n$summary" -ForegroundColor Green
