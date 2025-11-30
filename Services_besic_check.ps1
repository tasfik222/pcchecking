# =======================
#  CONFIG
# =======================
$VTApiKey = "fbea53db4a635688bccdc8b4241858cc5bb3ea55f6d2b91254b1c98f2d302191"
$LogPath = "AllServiceScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# =======================
#  FUNCTION: Logging
# =======================
function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    Write-Host $logEntry -ForegroundColor $(if ($Type -eq "ERROR") { "Red" } elseif ($Type -eq "WARNING") { "Yellow" } else { "White" })
    Add-Content -Path $LogPath -Value $logEntry
}

# =======================
#  FUNCTION: Signature Check
# =======================
function Get-SignatureStatus {
    param ([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) { return "FileNotFound" }
        $sig = Get-AuthenticodeSignature -FilePath $FilePath
        if ($sig.Status -eq "Valid") { return "Valid" }
        elseif ($sig.Status -eq "NotSigned") { return "NotSigned" }
        else { return $sig.Status.ToString() }
    } catch { "Error" }
}

# =======================
#  FUNCTION: Extract Executable Paths
# =======================
function Get-ExecutablePath {
    param([string]$PathName)
    
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    
    # Remove arguments and clean path
    $cleanPath = $PathName.Trim()
    
    # Handle quoted paths
    if ($cleanPath -match '^"([^"]+)"') {
        $path = $matches[1]
    }
    # Handle unquoted paths with spaces
    elseif ($cleanPath -match '^([^\s]+\.(exe|dll|sys|com|bat|cmd|ps1))') {
        $path = $matches[1]
    }
    # Handle svchost cases and other system processes
    elseif ($cleanPath -match '^([A-Z]:\\[^ ]+)') {
        $path = $matches[1]
    }
    else {
        $path = $cleanPath.Split(' ')[0]
    }
    
    # Expand environment variables
    if ($path -match '%([^%]+)%') {
        $path = [System.Environment]::ExpandEnvironmentVariables($path)
    }
    
    return $path
}

# =======================
#  FUNCTION: Get All Executable Files from Service
# =======================
function Get-ServiceExecutables {
    param([object]$Service)
    
    $executables = @()
    
    # Main service executable
    $mainExe = Get-ExecutablePath -PathName $Service.PathName
    if ($mainExe -and (Test-Path $mainExe)) {
        $executables += $mainExe
    }
    
    # Check for additional DLLs and dependencies
    try {
        # Get service process ID to find loaded modules
        if ($Service.State -eq "Running" -and $Service.ProcessId -gt 0) {
            $process = Get-Process -Id $Service.ProcessId -ErrorAction SilentlyContinue
            if ($process) {
                $modules = $process.Modules | Where-Object {
                    $_.ModuleName -like "*.dll" -or 
                    $_.ModuleName -like "*.exe" -or 
                    $_.ModuleName -like "*.sys"
                }
                foreach ($module in $modules) {
                    if (Test-Path $module.FileName) {
                        $executables += $module.FileName
                    }
                }
            }
        }
    }
    catch {
        # Silent continue if we can't access modules
    }
    
    return $executables | Sort-Object -Unique
}

# =======================
#  FUNCTION: VirusTotal Hash Scan
# =======================
function Check-VirusTotalHash {
    param([string]$FilePath)

    try {
        if (-not (Test-Path $FilePath)) {
            return @{
                Status = "File Not Found"
                RiskLevel = "Unknown"
            }
        }

        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
        Write-Host "  SHA256: $hash" -ForegroundColor Gray

        if ([string]::IsNullOrWhiteSpace($VTApiKey)) {
            return @{
                Hash = $hash
                Malicious = "API_KEY_REQUIRED"
                Suspicious = "API_KEY_REQUIRED"
                RiskLevel = "Unknown"
                Status = "API Key Not Configured"
            }
        }

        $url = "https://www.virustotal.com/api/v3/files/$hash"
        $headers = @{ "x-apikey" = $VTApiKey }

        Write-Host "  Querying VirusTotal..." -ForegroundColor Gray
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET

        $s = $response.data.attributes.last_analysis_stats
        $mal = $s.malicious
        $sus = $s.suspicious
        $total = $mal + $sus + $s.undetected + $s.harmless

        # Risk Logic
        $risk = "Clean"
        $state = "Safe"

        if ($mal -ge 5) { $risk="HIGH RISK"; $state="MALICIOUS" }
        elseif ($mal -ge 3) { $risk="MEDIUM RISK"; $state="Suspicious" }
        elseif ($mal -ge 1 -or $sus -ge 3) { $risk="LOW RISK"; $state="Suspicious" }
        elseif ($sus -ge 1) { $risk="MINOR RISK"; $state="Minor Suspicion" }

        return @{
            Hash = $hash
            Malicious = $mal
            Suspicious = $sus
            Detection = "$mal/$total"
            RiskLevel = $risk
            Status = $state
        }
    }
    catch {
        return @{ Status = "Scan Error"; RiskLevel = "Unknown" }
    }
}

# =======================
#  FUNCTION: File Details
# =======================
function Get-FileDetails {
    param([string]$FilePath)

    try {
        if (-not (Test-Path $FilePath)) {
            return @{ 
                Company = "N/A"
                Description = "N/A" 
                Version = "N/A" 
                FileSize = "N/A"
                ProductName = "N/A"
                FileType = "N/A"
            }
        }

        $file = Get-Item $FilePath
        $vi = $file.VersionInfo
        
        # Get file type
        $fileType = if ($file.Extension) { $file.Extension.ToUpper().Replace(".", "") } else { "Unknown" }

        return @{
            Company = if ($vi.CompanyName) { $vi.CompanyName } else { "N/A" }
            Description = if ($vi.FileDescription) { $vi.FileDescription } else { "N/A" }
            Version = if ($vi.FileVersion) { $vi.FileVersion } else { "N/A" }
            ProductName = if ($vi.ProductName) { $vi.ProductName } else { "N/A" }
            FileSize = "$([math]::Round($file.Length / 1KB, 2)) KB"
            FileType = $fileType
        }
    }
    catch {
        return @{ 
            Company = "Error"
            Description = "Error" 
            Version = "Error" 
            FileSize = "Error"
            ProductName = "Error"
            FileType = "Error"
        }
    }
}

# =======================
#  FUNCTION: Scan Single File
# =======================
function Scan-File {
    param(
        [string]$FilePath,
        [string]$ServiceName,
        [string]$ServiceDisplayName,
        [string]$ServiceState
    )
    
    $info = Get-FileDetails -FilePath $FilePath
    $sig = Get-SignatureStatus -FilePath $FilePath

    Write-Host "------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "📁 FILE SCAN: $($info.FileType) File" -ForegroundColor Yellow
    Write-Host "Service:       $ServiceName" -ForegroundColor Yellow
    Write-Host "Display Name:  $ServiceDisplayName" -ForegroundColor Yellow
    Write-Host "Status:        $ServiceState" -ForegroundColor Yellow
    Write-Host "Path:          $FilePath" -ForegroundColor Yellow
    Write-Host "Signature:     $sig" -ForegroundColor Yellow
    Write-Host "Company:       $($info.Company)" -ForegroundColor Yellow
    Write-Host "Product:       $($info.ProductName)" -ForegroundColor Yellow
    Write-Host "Description:   $($info.Description)" -ForegroundColor Yellow
    Write-Host "Version:       $($info.Version)" -ForegroundColor Yellow
    Write-Host "Size:          $($info.FileSize)" -ForegroundColor Yellow

    # VirusTotal Scan for suspicious files
    if ($sig -ne "Valid") {
        Write-Host "Scanning VirusTotal..." -ForegroundColor Gray
        $vt = Check-VirusTotalHash -FilePath $FilePath

        Write-Host "VirusTotal Result:" -ForegroundColor White
        Write-Host "  Malicious:  $($vt.Malicious)" -ForegroundColor White
        Write-Host "  Suspicious: $($vt.Suspicious)" -ForegroundColor White
        Write-Host "  Detection:  $($vt.Detection)" -ForegroundColor White
        Write-Host "  Risk:       $($vt.RiskLevel)" -ForegroundColor White
        Write-Host "  Status:     $($vt.Status)" -ForegroundColor White

        return @{
            FilePath = $FilePath
            FileType = $info.FileType
            Signature = $sig
            RiskLevel = $vt.RiskLevel
            Malicious = $vt.Malicious
            Suspicious = $vt.Suspicious
            IsSuspicious = ($vt.Malicious -ge 1 -or $vt.Suspicious -ge 3)
        }
    }
    else {
        Write-Host "✅ File is properly signed - Skipping VirusTotal scan" -ForegroundColor Green
        return @{
            FilePath = $FilePath
            FileType = $info.FileType
            Signature = $sig
            RiskLevel = "Clean"
            Malicious = 0
            Suspicious = 0
            IsSuspicious = $false
        }
    }
}

# =======================
#  MAIN SERVICE SCAN (ALL SERVICES + ALL EXECUTABLES)
# =======================
function Start-AllServiceScan {

    Write-Log "Starting COMPLETE SERVICE SECURITY SCAN..."
    Write-Log "Scanning ALL executable files (EXE, DLL, SYS, etc.)..."
    Write-Log "Log File: $LogPath"

    $services = Get-CimInstance Win32_Service
    Write-Log "Total Services Found: $($services.Count)"

    $scannedFiles = @{}
    $totalUnsigned = 0
    $totalSuspicious = 0
    $fileTypes = @{}

    foreach ($svc in $services) {
        Write-Host "`n=== Scanning Service: $($svc.Name) ===" -ForegroundColor Cyan
        Write-Host "Display Name: $($svc.DisplayName)" -ForegroundColor Cyan
        Write-Host "Status: $($svc.State)" -ForegroundColor Cyan

        try {
            # Get ALL executable files associated with this service
            $executables = Get-ServiceExecutables -Service $svc
            
            if ($executables.Count -eq 0) {
                Write-Host "  No accessible executable files found for this service" -ForegroundColor Gray
                continue
            }

            Write-Host "  Found $($executables.Count) executable file(s)" -ForegroundColor Gray

            foreach ($filePath in $executables) {
                # Skip already scanned files
                if ($scannedFiles.ContainsKey($filePath)) { 
                    Write-Host "  Already scanned: $filePath" -ForegroundColor DarkGray
                    continue 
                }

                $scannedFiles[$filePath] = $true

                # Scan the file
                $result = Scan-File -FilePath $filePath -ServiceName $svc.Name -ServiceDisplayName $svc.DisplayName -ServiceState $svc.State
                
                # Track file types
                $fileType = $result.FileType
                if ($fileTypes.ContainsKey($fileType)) {
                    $fileTypes[$fileType]++
                } else {
                    $fileTypes[$fileType] = 1
                }

                # Count results
                if ($result.Signature -ne "Valid") { $totalUnsigned++ }
                if ($result.IsSuspicious) { $totalSuspicious++ }

                # Alert for suspicious files
                if ($result.IsSuspicious) {
                    Write-Host "🚨 SECURITY ALERT: Suspicious file detected!" -ForegroundColor Red
                    Write-Host "   File: $($result.FilePath)" -ForegroundColor Red
                    Write-Host "   Risk Level: $($result.RiskLevel)" -ForegroundColor Red
                    Write-Host "   Detections: $($result.Malicious) malicious, $($result.Suspicious) suspicious" -ForegroundColor Red
                }

                Write-Host "------------------------------------------------------" -ForegroundColor Yellow
                
                # Rate limiting for VirusTotal API
                if ($result.Signature -ne "Valid") {
                    Start-Sleep -Milliseconds 500
                }
            }
        }
        catch {
            Write-Host "  Error scanning service: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # SUMMARY
    Write-Host "`n===== COMPREHENSIVE SCAN SUMMARY =====" -ForegroundColor Green
    Write-Host "Total Services Scanned:      $($services.Count)" -ForegroundColor White
    Write-Host "Total Unique Files Scanned:  $($scannedFiles.Count)" -ForegroundColor White
    Write-Host "Unsigned Files Found:        $totalUnsigned" -ForegroundColor Yellow
    Write-Host "Suspicious/Malicious Files:  $totalSuspicious" -ForegroundColor Red
    
    Write-Host "`nFile Types Scanned:" -ForegroundColor Green
    foreach ($type in $fileTypes.Keys | Sort-Object) {
        Write-Host "  $type : $($fileTypes[$type])" -ForegroundColor White
    }
    
    Write-Host "`nLog File Saved: $LogPath" -ForegroundColor Green
    
    if ($totalSuspicious -gt 0) {
        Write-Host "`n❌ SECURITY WARNING: Suspicious files detected!" -ForegroundColor Red
        Write-Host "   Please review the findings above." -ForegroundColor Red
    } else {
        Write-Host "`n✅ No major security threats detected." -ForegroundColor Green
    }
}

# =======================
#  RUN
# =======================
Write-Host "=== COMPLETE SERVICE SECURITY SCANNER ===" -ForegroundColor Green
Write-Host "Scanning ALL executable files (EXE, DLL, SYS, etc.)" -ForegroundColor Green
Write-Host "This may take several minutes..." -ForegroundColor Yellow

Start-AllServiceScan
