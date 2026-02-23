# File Counter Script
Write-Host "File Counter Script" -ForegroundColor Green
Write-Host "===================" -ForegroundColor Green

# Folder path input
$folderPath = Read-Host "Please enter the folder path"

# Check if folder exists
if (-not (Test-Path $folderPath)) {
    Write-Host "Error: Folder path does not exist!" -ForegroundColor Red
    exit
}

# Extension selection
Write-Host "`nSelect file type to count:" -ForegroundColor Yellow
Write-Host "1. EXE files only"
Write-Host "2. DLL files only"
Write-Host "3. All files"
$choice = Read-Host "Enter your choice (1, 2, or 3)"

# Count files based on choice
switch ($choice) {
    "1" { 
        $extension = "*.exe"
        $files = Get-ChildItem -Path $folderPath -Filter $extension -File
        $count = $files.Count
        Write-Host "`nNumber of EXE files: " -NoNewline
        Write-Host $count -ForegroundColor Green
    }
    "2" { 
        $extension = "*.dll"
        $files = Get-ChildItem -Path $folderPath -Filter $extension -File
        $count = $files.Count
        Write-Host "`nNumber of DLL files: " -NoNewline
        Write-Host $count -ForegroundColor Green
    }
    "3" { 
        $files = Get-ChildItem -Path $folderPath -File
        $count = $files.Count
        Write-Host "`nTotal number of files: " -NoNewline
        Write-Host $count -ForegroundColor Green
    }
    default {
        Write-Host "Invalid choice!" -ForegroundColor Red
        exit
    }
}

# Optional: List all files
$showList = Read-Host "`nDo you want to see the file list? (y/n)"
if ($showList -eq "y") {
    Write-Host "`nFile List:" -ForegroundColor Cyan
    $files | ForEach-Object { Write-Host $_.Name }
}

Write-Host "`nScript completed!" -ForegroundColor Green
