# =======================
#  CONFIG
# =======================
$VTApiKey = "fbea53db4a635688bccdc8b4241858cc5bb3ea55f6d2b91254b1c98f2d302191"
$LogPath = "ProcessScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# =======================
#  FUNCTION: Initialize Logging
# =======================
function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogPath -Value $logEntry
}

# =======================
#  FUNCTION: Check Signature
# =======================
function Get-SignatureStatus {
    param ([string]$EXEPath)

    try {
        if (-not (Test-Path $EXEPath)) { return "FileNotFound" }
        (Get-AuthenticodeSignature -FilePath $EXEPath).Status.ToString()
    }
    catch { "Error" }
}

# =======================
#  FUNCTION: VirusTotal Hash Check
# =======================
function Check-VirusTotalHash {
    param([string]$FilePath)

    try {
        $hash = (Get-FileHash $FilePath -Algorithm SHA256).Hash
        $headers = @{ "x-apikey" = $VTApiKey }
        $url = "https://www.virustotal.com/api/v3/files/$hash"

        $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        $stats = $response.data.attributes.last_analysis_stats

        $mal = $stats.malicious
        $sus = $stats.suspicious
        $total = $stats.harmless + $stats.undetected + $mal + $sus

        $risk = "Clean"
        if ($mal -ge 5) { $risk = "HIGH RISK" }
        elseif ($mal -ge 3) { $risk = "MEDIUM RISK" }
        elseif ($mal -ge 1 -or $sus -ge 3) { $risk = "LOW RISK" }

        return @{
            Hash = $hash
            Malicious = $mal
            Suspicious = $sus
            Detection = "$mal/$total"
            Risk = $risk
        }
    }
    catch {
        return @{ Hash="Error"; Malicious="Error"; Suspicious="Error"; Detection="N/A"; Risk="Unknown" }
    }
}

# =======================
#  FUNCTION: File Details
# =======================
function Get-FileDetails {
    param([string]$FilePath)

    try {
        $f = Get-Item $FilePath
        $v = $f.VersionInfo
        return @{
            Company = $v.CompanyName
            Description = $v.FileDescription
            Version = $v.FileVersion
            SizeKB = [math]::Round($f.Length / 1KB,2)
        }
    }
    catch {
        return @{ Company="N/A"; Description="N/A"; Version="N/A"; SizeKB="N/A" }
    }
}

# =======================
#  MAIN SCAN
# =======================
function Start-ProcessSecurityScan {

    Write-Log "Starting FULL C:\ process scan"

    $scannedFiles = @{}
    $unsigned = 0
    $suspicious = 0

    $processes = Get-Process -ErrorAction SilentlyContinue

    foreach ($p in $processes) {
        try {
            foreach ($m in $p.Modules) {

                $modulePath = $m.FileName

                # ONLY RULE: must be C:\
                if ([string]::IsNullOrEmpty($modulePath) `
                    -or -not ($modulePath.StartsWith("C:\")) `
                    -or $scannedFiles.ContainsKey($modulePath)) {
                    continue
                }

                $scannedFiles[$modulePath] = $true

                $sig = Get-SignatureStatus $modulePath

                if ($sig -ne "Valid") {

                    $unsigned++
                    Write-Host "`n============================" -ForegroundColor Yellow
                    Write-Host "Process : $($p.ProcessName)  PID:$($p.Id)" -ForegroundColor Yellow
                    Write-Host "Path    : $modulePath" -ForegroundColor Yellow
                    Write-Host "Signature: $sig" -ForegroundColor Yellow

                    $info = Get-FileDetails $modulePath
                    Write-Host "Company : $($info.Company)"
                    Write-Host "Desc    : $($info.Description)"
                    Write-Host "Version : $($info.Version)"
                    Write-Host "Size KB : $($info.SizeKB)"

                    Write-Host "VirusTotal Scan..." -ForegroundColor Gray
                    $vt = Check-VirusTotalHash $modulePath

                    Write-Host "Hash     : $($vt.Hash)"
                    Write-Host "Detection: $($vt.Detection)"
                    Write-Host "Risk     : $($vt.Risk)" -ForegroundColor Red

                    if ($vt.Malicious -ge 3) {
                        Write-Host "🚨 MALICIOUS FILE DETECTED" -ForegroundColor Red
                        $suspicious++
                    }

                    Start-Sleep -Milliseconds 500
                }
            }
        }
        catch {}
    }

    Write-Host "`n===== SCAN SUMMARY =====" -ForegroundColor Green
    Write-Host "Total unique files scanned: $($scannedFiles.Count)"
    Write-Host "Unsigned files found     : $unsigned"
    Write-Host "Suspicious files         : $suspicious"
    Write-Host "Log file saved to        : $LogPath" -ForegroundColor Green
}

# =======================
#  EXECUTION
# =======================
Write-Host "=== FULL C:\ PROCESS SECURITY SCANNER ===" -ForegroundColor Green

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "⚠️ Run as Administrator for full visibility" -ForegroundColor Yellow
}

Start-Sleep 2
Start-ProcessSecurityScan

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
