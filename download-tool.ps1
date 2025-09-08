# === Download all assets from GitHub release "tool" to Desktop\pccheckingtool ===
$Owner   = 'tasfik222'
$Repo    = 'pcchecking'
$TagName = 'tool'

# Ensure TLS 1.2 for GitHub
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Destination folder on Desktop
$desktop = [Environment]::GetFolderPath('Desktop')
$destDir = Join-Path $desktop 'pccheckingtool'
New-Item -ItemType Directory -Path $destDir -Force | Out-Null

# GitHub API endpoint for release by tag
$api = "https://api.github.com/repos/$Owner/$Repo/releases/tags/$TagName"
$headers = @{
  'User-Agent' = 'PowerShell'
  'Accept'     = 'application/vnd.github+json'
}

try {
    $release = Invoke-RestMethod -Uri $api -Headers $headers -ErrorAction Stop
} catch {
    Write-Host "❌ Release info আনতে পারিনি: $($_.Exception.Message)"
    Write-Host "➡️  লিংক ঠিক আছে কিনা দেখুন বা পরে চেষ্টা করুন।"
    exit 1
}

if (-not $release.assets -or $release.assets.Count -eq 0) {
    Write-Host "⚠️  এই রিলিজে কোন asset নেই।"
    exit 0
}

Write-Host "📥 ${Owner}/${Repo} :: tag '$TagName' থেকে মোট $($release.assets.Count)টা ফাইল নামানো হবে..."
$ok = 0; $fail = 0

foreach ($asset in $release.assets) {
    $url  = $asset.browser_download_url
    $name = $asset.name
    $out  = Join-Path $destDir $name

    Write-Host "  ⬇️  Downloading: $name"
    try {
        Invoke-WebRequest -Uri $url -OutFile $out -Headers @{ 'User-Agent' = 'PowerShell' } -UseBasicParsing -ErrorAction Stop
        $ok++
    } catch {
        Write-Host "    ❌ ব্যর্থ: $name — $($_.Exception.Message)"
        $fail++
    }
}

Write-Host ""
Write-Host "✅ ডাউনলোড শেষ!"
Write-Host "   ✅ সফল: $ok"
Write-Host "   ❌ ব্যর্থ: $fail"
Write-Host "📂 লোকেশন: $destDir"
