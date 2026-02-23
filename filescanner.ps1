Write-Host "Press Enter to Start..."
Read-Host

# API Key Input
$ApiKey = Read-Host "Enter your VirusTotal API Key"

# Folder Path Input
$FolderPath = Read-Host "Enter Folder Path to Scan"

# Extension Input with All Files Option
Write-Host "`nEnter file extension to scan (example: exe, dll, pdf)" -ForegroundColor Yellow
Write-Host "Or type 'all' to scan all files" -ForegroundColor Yellow
$Extension = Read-Host "Your choice"

# Validate Folder
if (!(Test-Path $FolderPath)) {
    Write-Host "Invalid Folder Path!" -ForegroundColor Red
    exit
}

# Get Files based on extension choice
if ($Extension -eq "all") {
    $Files = Get-ChildItem -Path $FolderPath -Recurse -File
    Write-Host "`nScanning ALL files in the directory..." -ForegroundColor Green
} else {
    $Files = Get-ChildItem -Path $FolderPath -Recurse -Filter "*.$Extension"
    Write-Host "`nScanning .$Extension files..." -ForegroundColor Green
}

if ($Files.Count -eq 0) {
    if ($Extension -eq "all") {
        Write-Host "No files found in the specified folder!" -ForegroundColor Yellow
    } else {
        Write-Host "No .$Extension files found!" -ForegroundColor Yellow
    }
    exit
}

$TotalFiles = $Files.Count
$CurrentFile = 0
$ScannedCount = 0
$FailedCount = 0

Write-Host "Total files to scan: $TotalFiles" -ForegroundColor Cyan

foreach ($File in $Files) {
    $CurrentFile++
    Write-Host "`n[$CurrentFile/$TotalFiles] Scanning: $($File.FullName)" -ForegroundColor Cyan
    Write-Host "File Size: $([math]::Round($File.Length/1MB, 2)) MB" -ForegroundColor Gray

    # Calculate SHA256
    try {
        $Hash = (Get-FileHash $File.FullName -Algorithm SHA256).Hash
    }
    catch {
        Write-Host "Failed to calculate hash for: $($File.FullName)" -ForegroundColor Red
        $FailedCount++
        continue
    }

    $Headers = @{
        "x-apikey" = $ApiKey
    }

    $ReportUrl = "https://www.virustotal.com/api/v3/files/$Hash"

    # Check if file exists in VT database
    try {
        $Response = Invoke-RestMethod -Uri $ReportUrl -Headers $Headers -Method Get -ErrorAction Stop
        
        # Show Results
        $Stats = $Response.data.attributes.last_analysis_stats
        Write-Host "--------------------------------------"
        Write-Host "File: $($File.Name)" -ForegroundColor White
        Write-Host "SHA256: $Hash" -ForegroundColor Gray
        Write-Host "--------------------------------------"
        Write-Host "Malicious : $($Stats.malicious)" -ForegroundColor Red
        Write-Host "Suspicious: $($Stats.suspicious)" -ForegroundColor Yellow
        Write-Host "Undetected: $($Stats.undetected)" -ForegroundColor Green
        Write-Host "Harmless  : $($Stats.harmless)" -ForegroundColor Green
        
        # Warning if malicious or suspicious
        if ($Stats.malicious -gt 0 -or $Stats.suspicious -gt 0) {
            Write-Host "⚠️  WARNING: This file may be dangerous!" -ForegroundColor Red
        }
        
        Write-Host "--------------------------------------"
        $ScannedCount++
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 404) {
            Write-Host "File not found in VT database. Uploading..." -ForegroundColor Yellow
            Write-Host "Note: File upload may take some time depending on size" -ForegroundColor Yellow
            
            $UploadUrl = "https://www.virustotal.com/api/v3/files"
            
            try {
                # Upload file
                $UploadResponse = Invoke-RestMethod -Uri $UploadUrl -Headers $Headers -Method Post -InFile $File.FullName -ContentType "multipart/form-data" -ErrorAction Stop
                
                Write-Host "Upload successful. Waiting for analysis (20 seconds)..." -ForegroundColor Green
                Start-Sleep -Seconds 20
                
                # Get report after upload
                $Response = Invoke-RestMethod -Uri $ReportUrl -Headers $Headers -Method Get -ErrorAction Stop
                
                # Show Results
                $Stats = $Response.data.attributes.last_analysis_stats
                Write-Host "--------------------------------------"
                Write-Host "File: $($File.Name)" -ForegroundColor White
                Write-Host "SHA256: $Hash" -ForegroundColor Gray
                Write-Host "--------------------------------------"
                Write-Host "Malicious : $($Stats.malicious)" -ForegroundColor Red
                Write-Host "Suspicious: $($Stats.suspicious)" -ForegroundColor Yellow
                Write-Host "Undetected: $($Stats.undetected)" -ForegroundColor Green
                Write-Host "Harmless  : $($Stats.harmless)" -ForegroundColor Green
                
                if ($Stats.malicious -gt 0 -or $Stats.suspicious -gt 0) {
                    Write-Host "⚠️  WARNING: This file may be dangerous!" -ForegroundColor Red
                }
                
                Write-Host "--------------------------------------"
                $ScannedCount++
            }
            catch {
                if ($_.Exception.Response.StatusCode.value__ -eq 429) {
                    Write-Host "`n🚫 API LIMIT REACHED! Please wait..." -ForegroundColor Red
                    Write-Host "Waiting 60 seconds before continuing..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 60
                }
                else {
                    Write-Host "Upload Failed for: $($File.FullName)" -ForegroundColor Red
                    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
                    $FailedCount++
                }
            }
        }
        elseif ($_.Exception.Response.StatusCode.value__ -eq 429) {
            Write-Host "`n🚫 API LIMIT REACHED! Please wait..." -ForegroundColor Red
            Write-Host "Waiting 60 seconds before continuing..." -ForegroundColor Yellow
            Start-Sleep -Seconds 60
        }
        else {
            Write-Host "Error checking file: $($File.FullName)" -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            $FailedCount++
        }
    }
    
    # Add delay between requests to avoid rate limiting
    if ($CurrentFile -lt $TotalFiles) {
        Write-Host "Waiting 3 seconds before next file..." -ForegroundColor Gray
        Start-Sleep -Seconds 3
    }
}

# Summary
Write-Host "`n" + "="*50 -ForegroundColor Cyan
Write-Host "SCAN COMPLETED!" -ForegroundColor Green
Write-Host "="*50 -ForegroundColor Cyan
Write-Host "Total Files Scanned: $ScannedCount" -ForegroundColor White
Write-Host "Failed/Skipped: $FailedCount" -ForegroundColor Yellow
Write-Host "Total Processed: $TotalFiles" -ForegroundColor White

if ($ScannedCount -gt 0) {
    Write-Host "`nScan results saved in memory. Check above for details." -ForegroundColor Gray
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
