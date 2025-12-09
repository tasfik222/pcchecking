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
    Write-Host $logEntry -ForegroundColor $(if ($Type -eq "ERROR") { "Red" } elseif ($Type -eq "WARNING") { "Yellow" } else { "White" })
    Add-Content -Path $LogPath -Value $logEntry
}

# =======================
#  FUNCTION: Full Signature Check (Fake Signature Detection)
# =======================
function Get-SignatureStatus {
    param ([string]$EXEPath)

    try {
        if (-not (Test-Path $EXEPath)) {
            return "FileNotFound"
        }

        $sig = Get-AuthenticodeSignature -FilePath $EXEPath

        # No signature
        if ($sig.Status -eq "NotSigned") {
            return "NotSigned"
        }

        # Broken or invalid signature
        if ($sig.Status -ne "Valid") {
            return "TamperedSignature"
        }

        # Extra verification
        $cert = $sig.SignerCertificate

        # Certificate expired → fake or reused cert
        if ($cert.NotAfter -lt (Get-Date)) {
            return "FakeSignature_ExpiredCert"
        }

        # Certificate not valid yet → manipulated
        if ($cert.NotBefore -gt (Get-Date)) {
            return "FakeSignature_FutureCert"
        }

        # Validate certificate chain
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $trusted = $chain.Build($cert)

        if (-not $trusted) {
            return "FakeSignature_UntrustedChain"
        }

        # Suspicious Issuer (cheap CA)
        $issuer = $cert.Issuer
        if ($issuer -notmatch "Microsoft|Google|Adobe|NVIDIA|Intel|Dell|HP|Valve|Steam|AMD|Cisco|Oracle") {
            return "SuspiciousIssuer"
        }

        return "Valid"
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
            return @{ Status = "FileNotFound"; RiskLevel = "Unknown"; Hash="N/A"; Malicious="N/A"; Suspicious="N/A" }
        }

        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash

        if ([string]::IsNullOrWhiteSpace($VTApiKey)) {
            return @{ Status = "APIKeyMissing"; Hash=$hash }
        }

        $url = "https://www.virustotal.com/api/v3/files/$hash"
        $headers = @{ "x-apikey" = $VTApiKey }

        $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers

        $stats = $response.data.attributes.last_analysis_stats
        $mal = $stats.malicious
        $sus = $stats.suspicious

        # Risk Logic
        if ($mal -ge 5) { $risk = "HIGH RISK"; $st="MALICIOUS" }
        elseif ($mal -ge 3) { $risk = "MEDIUM RISK"; $st="Suspicious" }
        elseif ($mal -ge 1 -or $sus -ge 3) { $risk = "LOW RISK"; $st="Suspicious" }
        elseif ($sus -ge 1) { $risk = "MINOR RISK"; $st="Minor" }
        else { $risk = "Clean"; $st="Safe" }

        return @{
            Hash=$hash
            Malicious=$mal
            Suspicious=$sus
            DetectionRatio="$mal/$($stats.harmless+$stats.undetected+$mal+$sus)"
            RiskLevel=$risk
            Status=$st
        }
    }
    catch {
        return @{ Status="Error"; RiskLevel="Unknown"; Hash="Error" }
    }
}

# =======================
#  FUNCTION: Get File Information
# =======================
function Get-FileDetails {
    param([string]$FilePath)

    try {
        $file = Get-Item $FilePath
        $v = $file.VersionInfo

        return @{
            Company = $v.CompanyName
            Description = $v.FileDescription
            Version = $v.FileVersion
            FileSize = "$([math]::Round($file.Length / 1KB, 2)) KB"
        }
    }
    catch {
        return @{ Company="N/A"; Description="N/A"; Version="N/A"; FileSize="N/A" }
    }
}

# =======================
#  MAIN PROCESS SCAN
# =======================
function Start-ProcessSecurityScan {
    
    Write-Log "Starting process scan..."
    $scanned = @{}
    $unsigned = 0
    $suspicious = 0

    $procs = Get-Process

    foreach ($p in $procs) {
        try {
            foreach ($m in $p.Modules) {

                $path = $m.FileName

                if (-not $path -or $scanned.ContainsKey($path)) { continue }
                if ($path -like "*System32*" -or $path -like "*Windows*") { continue }

                $scanned[$path] = $true

                Write-Host "`nScanning: $path" -ForegroundColor Cyan

                # Signature Check
                $sig = Get-SignatureStatus $path

                if ($sig -ne "Valid") {
                    $unsigned++

                    Write-Host "Signature: $sig" -ForegroundColor Yellow
                    $info = Get-FileDetails $path
                    Write-Host "Company: $($info.Company)"
                    Write-Host "Description: $($info.Description)"
                    Write-Host "Version: $($info.Version)"
                    Write-Host "Size: $($info.FileSize)"

                    Write-Host "VirusTotal Checking..." -ForegroundColor Gray
                    $vt = Check-VirusTotalHash $path

                    Write-Host "VT Result: $($vt.RiskLevel)" -ForegroundColor Red

                    if ($vt.Malicious -ge 3 -or $sig -like "FakeSignature*") {
                        Write-Host "🚨 HIGH RISK FILE DETECTED!" -ForegroundColor Red
                        $suspicious++
                    }
                }

                Start-Sleep -Milliseconds 400
            }
        }
        catch {}
    }

    Write-Host "`n--- SCAN SUMMARY ---" -ForegroundColor Green
    Write-Host "Total Files Scanned: $($scanned.Count)"
    Write-Host "Unsigned / Fake Signature Files: $unsigned" -ForegroundColor Yellow
    Write-Host "Suspicious Files: $suspicious" -ForegroundColor Red
    Write-Host "Log saved: $LogPath"
}

# =======================
#  START
# =======================
Write-Host "Starting in 3 seconds..."
Start-Sleep 3
Start-ProcessSecurityScan
