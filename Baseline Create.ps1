Write-Host "Scanning full PC for all EXE and DLL files... This may take a moment." -ForegroundColor Cyan

$baselineFile = "C:\ProgramData\pc_files_baseline.txt"

# Scan for both EXE and DLL files
$fileList = Get-ChildItem -Path "C:\" -Include *.exe, *.dll -Recurse -ErrorAction SilentlyContinue

# Save full paths to baseline file
$fileList.FullName | Out-File $baselineFile -Encoding UTF8

Write-Host "`n[✔] Baseline created successfully!" -ForegroundColor Green
Write-Host "Total EXE and DLL files saved: $($fileList.Count)"
Write-Host "Saved at: $baselineFile"
