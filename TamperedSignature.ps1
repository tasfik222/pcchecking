# =======================
# CONFIG
# =======================
$VTApiKey = "fbea53db4a635688bccdc8b4241858cc5bb3ea55f6d2b91254b1c98f2d302191"
$LogPath = "ProcessScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# =======================
# GLOBAL COLLECTIONS
# =======================
$ScannedFiles   = @{}
$TamperedFiles  = @{}

# =======================
# LOGGING
# =======================
function Write-Log {
    param([string]$Message,[string]$Type="INFO")
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $e = "[$t][$Type] $Message"
    Write-Host $e
    Add-Content $LogPath $e
}

# =======================
# SIGNATURE CHECK
# =======================
function Get-SignatureStatus {
    param($Path)
    try {
        if (-not (Test-Path $Path)) { return "Missing" }
        $sig = Get-AuthenticodeSignature $Path
        if ($sig.Status -eq "NotSigned") { return "NotSigned" }
        if ($sig.Status -ne "Valid") { return "TamperedSignature" }
        return "Valid"
    } catch { return "Error" }
}

# =======================
# VIRUSTOTAL
# =======================
function Check-VT {
    param($Path)
    try {
        $hash = (Get-FileHash $Path -Algorithm SHA256).Hash
        if (-not $VTApiKey) { return @{ Risk="NO_API"; Hash=$hash } }

        $h = @{ "x-apikey" = $VTApiKey }
        $u = "https://www.virustotal.com/api/v3/files/$hash"
        $r = Invoke-RestMethod $u -Headers $h -ErrorAction Stop

        $s = $r.data.attributes.last_analysis_stats
        if ($s.malicious -ge 3) { $risk="HIGH" }
        elseif ($s.malicious -ge 1) { $risk="LOW" }
        else { $risk="CLEAN" }

        return @{ Risk=$risk; Malicious=$s.malicious }
    } catch {
        return @{ Risk="ERROR" }
    }
}

# =======================
# FILE SCAN
# =======================
function Scan-File {
    param($Path,$Type)

    if ($ScannedFiles.ContainsKey($Path)) { return }
    $ScannedFiles[$Path] = $true

    Write-Host "`n[$Type] Scanning: $Path" -ForegroundColor Cyan

    $sig = Get-SignatureStatus $Path

    if ($sig -ne "Valid") {
        Write-Host " Signature: $sig" -ForegroundColor Yellow

        # Store tampered files
        if (-not $TamperedFiles.ContainsKey($Path)) {
            $TamperedFiles[$Path] = $sig
        }

        $vt = Check-VT $Path
        Write-Host " VT Risk: $($vt.Risk)" -ForegroundColor Red
    }

    Start-Sleep -Milliseconds 200
}

# =======================
# MAIN SCAN
# =======================
function Start-FullScan {

    Write-Log "Starting FULL EXE + DLL scan"

    $procs = Get-Process -ErrorAction SilentlyContinue

    foreach ($p in $procs) {
        try {
            # Scan main EXE
            if ($p.Path) {
                Scan-File $p.Path "PROCESS"
            }

            # Scan loaded modules (DLL)
            foreach ($m in $p.Modules) {
                try {
                    if ($m.FileName) {
                        Scan-File $m.FileName "MODULE"
                    }
                } catch {}
            }
        }
        catch {
            Write-Log "Access denied: $($p.ProcessName)" "WARNING"
        }
    }

    # =======================
    # SUMMARY
    # =======================
    Write-Host "`n========== FINAL SUMMARY ==========" -ForegroundColor Green
    Write-Host "Total Files Scanned   : $($ScannedFiles.Count)"
    Write-Host "Tampered / Unsigned   : $($TamperedFiles.Count)" -ForegroundColor Red

    if ($TamperedFiles.Count -gt 0) {
        Write-Host "`n--- TAMPERED FILE LIST ---" -ForegroundColor Yellow
        foreach ($k in $TamperedFiles.Keys) {
            Write-Host "[$($TamperedFiles[$k])] $k" -ForegroundColor Red
        }
    }

    Write-Host "`nLog saved to: $LogPath"
}

# =======================
# START
# =======================
Write-Host "Starting scan in 3 seconds..."
Start-Sleep 3
Start-FullScan
