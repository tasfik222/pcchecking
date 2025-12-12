$baselineFile = "C:\ProgramData\pc_files_baseline.txt"

# Check if baseline exists
if (!(Test-Path $baselineFile)) {
    Write-Host "[ERROR] Baseline not found! Run baseline script first." -ForegroundColor Red
    exit
}

Write-Host "Checking for deleted EXE and DLL files..." -ForegroundColor Yellow

# Read baseline
$baseline = Get-Content $baselineFile
$missing = @()

foreach ($file in $baseline) {
    if (!(Test-Path $file)) {
        $missing += $file
    }
}

if ($missing.Count -eq 0) {
    Write-Host "`n[✔] No EXE or DLL files deleted." -ForegroundColor Green
} else {
    Write-Host "`n[⚠] Deleted EXE/DLL files detected:" -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "  - $m" -ForegroundColor Red
    }

    # Save missing result
    $missingFile = "C:\ProgramData\deleted_files_list.txt"
    $missing | Out-File $missingFile -Encoding UTF8
    Write-Host "`nSaved list: $missingFile" -ForegroundColor Cyan
}
