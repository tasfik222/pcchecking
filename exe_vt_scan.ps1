# ===========================================================
# VirusTotal Hash Scanner - Full PC EXE Scan
# Works on PowerShell 5.x and 7.x
# ===========================================================

$ApiKey = "fbea53db4a635688bccdc8b4241858cc5bb3ea55f6d2b91254b1c98f2d302191"
$LogFile = "C:\VirusTotal_Scan_Log.txt"

"=== VirusTotal Hash Scan Started at $(Get-Date) ===" | Out-File $LogFile

# Get all EXE files from C: drive
$ExeFiles = Get-ChildItem -Path C:\ -Filter *.exe -File -Recurse -ErrorAction SilentlyContinue

foreach ($File in $ExeFiles) {

    try {
        Write-Host "`nChecking: $($File.FullName)" -ForegroundColor Cyan

        # Calculate SHA256 hash
        $Sha256 = Get-FileHash -Path $File.FullName -Algorithm SHA256 | Select-Object -ExpandProperty Hash

        # VirusTotal API URL
        $VTurl = "https://www.virustotal.com/api/v3/files/$Sha256"

        # Send request to VirusTotal
        $Response = Invoke-RestMethod -Method Get -Uri $VTurl -Headers @{
            "x-apikey" = $ApiKey
        } -ErrorAction Stop

        # Extract detection info
        $Stats = $Response.data.attributes.last_analysis_stats
        $Malicious = $Stats.malicious
        $Suspicious = $Stats.suspicious
        $Undetected = $Stats.undetected

        $LogText = "[$(Get-Date)] File: $($File.FullName)`nSHA256: $Sha256`nMalicious: $Malicious | Suspicious: $Suspicious | Undetected: $Undetected`n---"
        $LogText | Out-File $LogFile -Append

    } catch {
        "[$(Get-Date)] ERROR scanning $($File.FullName): $_" | Out-File $LogFile -Append
    }

    # To prevent rate limits
    Start-Sleep -Milliseconds 600
}

"=== Scan Completed at $(Get-Date) ===" | Out-File $LogFile -Append
Write-Host "`n=== SCAN FINISHED ===" -ForegroundColor Green
