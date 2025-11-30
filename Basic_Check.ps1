# =======================
#  CONFIG
# =======================
$VTApiKey = "fbea53db4a635688bccdc8b4241858cc5bb3ea55f6d2b91254b1c98f2d302191"   # <-- Put your API key here
$LogPath = "ProcessScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# =======================
#  FUNCTION: Initialize Logging
# =======================
function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    Write-Host $logEntry -ForegroundColor $(if ($Type -eq "ERROR") { "Red" } elseif ($Type -eq "WARNING") { "Yellow" } else { "White" })
    Add-Content -Path $LogPath -Value $logEntry
}

# =======================
#  FUNCTION: Check Signature
# =======================
function Get-SignatureStatus {
    param ([string]$EXEPath)
    
    try {
        if (-not (Test-Path $EXEPath)) {
            return "FileNotFound"
        }
        
        $signature = Get-AuthenticodeSignature -FilePath $EXEPath
        return $signature.Status.ToString()
    }
    catch {
        return "Error"
    }
}

# =======================
#  FUNCTION: Scan Hash in VirusTotal
# =======================
function Check-VirusTotalHash {
    param([string]$FilePath)

    try {
        if (-not (Test-Path $FilePath)) {
            return @{ 
                Hash = "FileNotFound"
                Malicious = "N/A" 
                Suspicious = "N/A"
                Status = "File Not Found"
                RiskLevel = "Unknown"
            }
        }

        # Calculate SHA256 hash
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash

        Write-Host "  Calculating hash: $hash" -ForegroundColor Gray

        # Check API key
        if ($VTApiKey -eq "YOUR_VIRUSTOTAL_API_KEY" -or [string]::IsNullOrWhiteSpace($VTApiKey)) {
            return @{ 
                Hash = $hash
                Malicious = "API_Key_Required" 
                Suspicious = "API_Key_Required"
                Status = "API Key Not Configured"
                RiskLevel = "Unknown"
            }
        }

        $url = "https://www.virustotal.com/api/v3/files/$hash"
        $headers = @{ "x-apikey" = $VTApiKey }

        Write-Host "  Querying VirusTotal..." -ForegroundColor Gray
        $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers -ErrorAction Stop

        $stats = $response.data.attributes.last_analysis_stats
        $malicious = $stats.malicious
        $suspicious = $stats.suspicious
        $undetected = $stats.undetected
        $harmless = $stats.harmless
        $total = $malicious + $suspicious + $undetected + $harmless

        # Risk Assessment Logic
        $riskLevel = "Clean"
        $status = "Safe"

        if ($malicious -ge 5) {
            $riskLevel = "HIGH RISK"
            $status = "MALICIOUS"
        }
        elseif ($malicious -ge 3) {
            $riskLevel = "MEDIUM RISK"
            $status = "Suspicious"
        }
        elseif ($malicious -ge 1 -or $suspicious -ge 3) {
            $riskLevel = "LOW RISK"
            $status = "Suspicious"
        }
        elseif ($suspicious -ge 1) {
            $riskLevel = "MINOR RISK"
            $status = "Minor Suspicion"
        }

        return @{
            Hash = $hash
            Malicious = $malicious
            Suspicious = $suspicious
            TotalEngines = $total
            DetectionRatio = "$malicious/$total"
            RiskLevel = $riskLevel
            Status = $status
        }
    }
    catch {
        return @{ 
            Hash = "Unknown"
            Malicious = "Error" 
            Suspicious = "Error"
            Status = "Scan Error"
            RiskLevel = "Unknown"
        }
    }
}

# =======================
#  FUNCTION: Get File Information
# =======================
function Get-FileDetails {
    param([string]$FilePath)
    
    try {
        if (-not (Test-Path $FilePath)) {
            return @{ Company = "N/A"; Description = "N/A"; Version = "N/A"; FileSize = "N/A" }
        }
        
        $fileInfo = Get-Item $FilePath
        $versionInfo = $fileInfo.VersionInfo
        
        return @{
            Company = if ($versionInfo.CompanyName) { $versionInfo.CompanyName } else { "N/A" }
            Description = if ($versionInfo.FileDescription) { $versionInfo.FileDescription } else { "N/A" }
            Version = if ($versionInfo.FileVersion) { $versionInfo.FileVersion } else { "N/A" }
            FileSize = "$([math]::Round($fileInfo.Length / 1KB, 2)) KB"
        }
    }
    catch {
        return @{ Company = "Error"; Description = "Error"; Version = "Error"; FileSize = "Error" }
    }
}

# =======================
#  MAIN PROCESS SCAN
# =======================
function Start-ProcessSecurityScan {
    Write-Log "Starting process security scan..."
    Write-Log "Log file: $LogPath"
    
    # Track scanned files to avoid duplicates
    $scannedFiles = @{}
    $unsignedCount = 0
    $suspiciousCount = 0
    
    try {
        $allProcesses = Get-Process -ErrorAction SilentlyContinue
        
        Write-Log "Found $($allProcesses.Count) running processes"
        
        foreach ($process in $allProcesses) {
            try {
                Write-Host "`nChecking process: $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Cyan
                
                # Skip system processes to reduce noise
                if ($process.ProcessName -eq "Idle" -or $process.ProcessName -eq "System") {
                    continue
                }
                
                $modules = $process.Modules

                foreach ($module in $modules) {
                    try {
                        $modulePath = $module.FileName
                        
                        # Skip if no path or already scanned
                        if ([string]::IsNullOrEmpty($modulePath) -or $scannedFiles.ContainsKey($modulePath)) {
                            continue
                        }
                        
                        # Skip Windows system files
                        if ($modulePath -like "*\System32\*" -or 
                            $modulePath -like "*\SysWOW64\*" -or 
                            $modulePath -like "*\Windows\*" -or
                            $modulePath -like "*\Program Files\*" -or
                            $modulePath -like "*\Program Files (x86)\*") {
                            continue
                        }
                        
                        $scannedFiles[$modulePath] = $true
                        
                        # Check signature
                        $signatureStatus = Get-SignatureStatus -EXEPath $modulePath
                        
                        if ($signatureStatus -ne "Valid") {
                            $unsignedCount++
                            $fileDetails = Get-FileDetails -FilePath $modulePath
                            
                            Write-Host "------------------------------------------------------" -ForegroundColor Yellow
                            Write-Host "Unsigned or Invalid EXE Found:" -ForegroundColor Yellow
                            Write-Host "Process:    $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Yellow
                            Write-Host "Module:     $($module.ModuleName)" -ForegroundColor Yellow
                            Write-Host "Path:       $modulePath" -ForegroundColor Yellow
                            Write-Host "Signature:  $signatureStatus" -ForegroundColor Yellow
                            Write-Host "Company:    $($fileDetails.Company)" -ForegroundColor Yellow
                            Write-Host "Description:$($fileDetails.Description)" -ForegroundColor Yellow
                            Write-Host "Version:    $($fileDetails.Version)" -ForegroundColor Yellow
                            Write-Host "File Size:  $($fileDetails.FileSize)" -ForegroundColor Yellow
                            
                            # VirusTotal scan
                            Write-Host "Scanning VirusTotal..." -ForegroundColor Gray
                            $vtResult = Check-VirusTotalHash -FilePath $modulePath
                            
                            # Display results
                            Write-Host "VirusTotal Results:" -ForegroundColor White
                            Write-Host "SHA256:     $($vtResult.Hash)" -ForegroundColor Gray
                            Write-Host "Malicious:  $($vtResult.Malicious)" -ForegroundColor $(if ($vtResult.Malicious -gt 0) { "Red" } else { "Gray" })
                            Write-Host "Suspicious: $($vtResult.Suspicious)" -ForegroundColor $(if ($vtResult.Suspicious -gt 0) { "Yellow" } else { "Gray" })
                            Write-Host "Detection:  $($vtResult.DetectionRatio)" -ForegroundColor Gray
                            Write-Host "Risk Level: $($vtResult.RiskLevel)" -ForegroundColor $(if ($vtResult.RiskLevel -eq "HIGH RISK") { "Red" } elseif ($vtResult.RiskLevel -eq "MEDIUM RISK") { "Yellow" } else { "Gray" })
                            Write-Host "Status:     $($vtResult.Status)" -ForegroundColor $(if ($vtResult.Status -eq "MALICIOUS") { "Red" } elseif ($vtResult.Status -eq "Suspicious") { "Yellow" } else { "Gray" })
                            
                            # Alert for dangerous files
                            if ($vtResult.Malicious -ge 3) {
                                Write-Host "🚨 DANGER: This file is detected as MALICIOUS by $($vtResult.Malicious) engines!" -ForegroundColor Red
                                Write-Host "🚨 Recommended action: Investigate immediately!" -ForegroundColor Red
                                $suspiciousCount++
                            }
                            elseif ($vtResult.Malicious -ge 1 -or $vtResult.Suspicious -ge 3) {
                                Write-Host "⚠️ WARNING: This file shows suspicious activity!" -ForegroundColor Yellow
                                $suspiciousCount++
                            }
                            
                            Write-Host "------------------------------------------------------" -ForegroundColor Yellow
                            
                            # Small delay to avoid rate limiting
                            Start-Sleep -Milliseconds 500
                        }
                    }
                    catch {
                        # Skip module errors
                    }
                }
            }
            catch {
                # Skip process errors
            }
        }
        
        # Summary
        Write-Host "`n=== SCAN SUMMARY ===" -ForegroundColor Green
        Write-Host "Total processes scanned: $($allProcesses.Count)" -ForegroundColor White
        Write-Host "Total unique files checked: $($scannedFiles.Count)" -ForegroundColor White
        Write-Host "Unsigned/invalid files found: $unsignedCount" -ForegroundColor $(if ($unsignedCount -gt 0) { "Yellow" } else { "White" })
        Write-Host "Suspicious files detected: $suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) { "Red" } else { "White" })
        Write-Host "Scan completed. Log saved to: $LogPath" -ForegroundColor Green
        
    }
    catch {
        Write-Host "Error during process scan: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# =======================
#  EXECUTION
# =======================
Write-Host "=== Process Security Scanner ===" -ForegroundColor Green
Write-Host "This script scans running processes for unsigned executables" -ForegroundColor Gray
Write-Host "and checks them against VirusTotal." -ForegroundColor Gray
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "Warning: Not running as administrator. Some processes may not be accessible." -ForegroundColor Yellow
}

# Check API key
if ($VTApiKey -eq "YOUR_VIRUSTOTAL_API_KEY" -or [string]::IsNullOrWhiteSpace($VTApiKey)) {
    Write-Host "Warning: VirusTotal API key not configured. VirusTotal scanning will not work." -ForegroundColor Yellow
    Write-Host "Get free API key from: https://www.virustotal.com/gui/join-us" -ForegroundColor Gray
}

Write-Host "`nStarting scan in 3 seconds..." -ForegroundColor Gray
Start-Sleep -Seconds 3

# Start the scan
Start-ProcessSecurityScan

Write-Host "`nPress any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
