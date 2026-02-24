Write-Host "Scanning full PC for ALL files... This may take a moment." -ForegroundColor Cyan

$baselineFile = "C:\ProgramData\pc_files_baseline.txt"

# Scan for ALL files (any extension)
$fileList = Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue

# Save full paths to baseline file
$fileList.FullName | Out-File $baselineFile -Encoding UTF8

Write-Host "`n[✔] Baseline created successfully!" -ForegroundColor Green
Write-Host "Total files saved: $($fileList.Count)"
Write-Host "Saved at: $baselineFile"
