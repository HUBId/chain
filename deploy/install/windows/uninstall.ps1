$ErrorActionPreference = 'Stop'
$targetDir = Join-Path -Path $env:ProgramFiles -ChildPath 'RPP Wallet'
if (Test-Path $targetDir) {
    Remove-Item -Recurse -Force -Path $targetDir
}
$envPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($envPath -and $envPath.Contains($targetDir)) {
    $newPath = ($envPath -split ';' | Where-Object { $_ -ne $targetDir }) -join ';'
    [Environment]::SetEnvironmentVariable('PATH', $newPath, 'User')
}
$shortcutDir = Join-Path -Path ([Environment]::GetFolderPath('Programs')) -ChildPath 'RPP'
$shortcut = Join-Path -Path $shortcutDir -ChildPath 'RPP Wallet.lnk'
if (Test-Path $shortcut) {
    Remove-Item -Force $shortcut
}
Write-Host "Removed RPP Wallet and associated shortcuts."
