Write-Host "Press Enter to Start..."
Read-Host

# API Key Input
$ApiKey = Read-Host "Enter your VirusTotal API Key"

# Folder Path Input
$FolderPath = Read-Host "Enter Folder Path to Scan"

# Extension Input
$Extension = Read-Host "Enter file extension to scan (example: exe or dll)"

# Validate Folder
if (!(Test-Path $FolderPath)) {
    Write-Host "Invalid Folder Path!" -ForegroundColor Red
    exit
}

# Get Files
$Files = Get-ChildItem -Path $FolderPath -Recurse -Filter "*.$Extension"

if ($Files.Count -eq 0) {
    Write-Host "No .$Extension files found!" -ForegroundColor Yellow
    exit
}

foreach ($File in $Files) {

    Write-Host "`nScanning: $($File.FullName)" -ForegroundColor Cyan

    # Calculate SHA256
    $Hash = (Get-FileHash $File.FullName -Algorithm SHA256).Hash

    $Headers = @{
        "x-apikey" = $ApiKey
    }

    $ReportUrl = "https://www.virustotal.com/api/v3/files/$Hash"

    try {
        $Response = Invoke-RestMethod -Uri $ReportUrl -Headers $Headers -Method Get -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 429) {
            Write-Host "`n🚫 API LIMIT REACHED! Try again later." -ForegroundColor Red
            exit
        }

        Write-Host "File not found in VT database. Uploading..." -ForegroundColor Yellow
        
        $UploadUrl = "https://www.virustotal.com/api/v3/files"

        try {
            $UploadResponse = Invoke-RestMethod -Uri $UploadUrl -Headers $Headers -Method Post -InFile $File.FullName -ContentType "multipart/form-data" -ErrorAction Stop
            
            Start-Sleep -Seconds 20
            
            $Response = Invoke-RestMethod -Uri $ReportUrl -Headers $Headers -Method Get -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                Write-Host "`n🚫 API LIMIT REACHED during upload! Try again later." -ForegroundColor Red
                exit
            }

            Write-Host "Upload Failed!" -ForegroundColor Red
            continue
        }
    }

    # Show Results
    $Stats = $Response.data.attributes.last_analysis_stats

    Write-Host "--------------------------------------"
    Write-Host "Malicious : $($Stats.malicious)" -ForegroundColor Red
    Write-Host "Suspicious: $($Stats.suspicious)" -ForegroundColor Yellow
    Write-Host "Undetected: $($Stats.undetected)" -ForegroundColor Green
    Write-Host "Harmless  : $($Stats.harmless)" -ForegroundColor Green
    Write-Host "--------------------------------------"
}

Write-Host "`nScan Completed!"
