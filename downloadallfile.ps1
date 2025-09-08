# Desktop path বের করা
$desktopPath = [Environment]::GetFolderPath("Desktop")
$targetFolder = Join-Path $desktopPath "pcchecking"

# যদি ফোল্ডার না থাকে তবে তৈরি করবে
if (-Not (Test-Path $targetFolder)) {
    New-Item -ItemType Directory -Path $targetFolder | Out-Null
}

# ZIP ডাউনলোড করার লিংক
$zipUrl = "https://github.com/tasfik222/pcchecking/archive/refs/heads/main.zip"
$zipFile = Join-Path $desktopPath "pcchecking.zip"

# ZIP ফাইল ডাউনলোড করা
Invoke-WebRequest -Uri $zipUrl -OutFile $zipFile

# ZIP Extract করা
Expand-Archive -Path $zipFile -DestinationPath $desktopPath -Force

# Extract হওয়া ফোল্ডারের ভেতরের কনটেন্ট pcchecking এ মুভ করা
Move-Item -Path (Join-Path $desktopPath "pcchecking-main\*") -Destination $targetFolder -Force

# অপ্রয়োজনীয় ফাইল/ফোল্ডার মুছে ফেলা
Remove-Item $zipFile -Force
Remove-Item (Join-Path $desktopPath "pcchecking-main") -Recurse -Force

Write-Host "✅ All files downloaded to: $targetFolder"
