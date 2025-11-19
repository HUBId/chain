$ErrorActionPreference = 'Stop'
$payloadRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$binRoot = Join-Path $payloadRoot '..' | Resolve-Path
$walletRoot = (Join-Path -Path $binRoot -ChildPath '..' | Resolve-Path).Path
$targetDir = Join-Path -Path $env:ProgramFiles -ChildPath 'RPP Wallet'

New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
Copy-Item -Path (Join-Path $walletRoot 'bin/*') -Destination $targetDir -Recurse -Force
Copy-Item -Path (Join-Path $walletRoot 'config/*') -Destination (Join-Path $targetDir 'config') -Recurse -Force
Copy-Item -Path (Join-Path $walletRoot 'docs/*') -Destination (Join-Path $targetDir 'docs') -Recurse -Force
Copy-Item -Path (Join-Path $walletRoot 'hooks/*') -Destination (Join-Path $targetDir 'hooks') -Recurse -Force -ErrorAction SilentlyContinue

$envPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if (-not $envPath.Contains($targetDir)) {
    [Environment]::SetEnvironmentVariable('PATH', "$targetDir;$envPath", 'User')
}

$shortcutDir = Join-Path -Path ([Environment]::GetFolderPath('Programs')) -ChildPath 'RPP'
New-Item -ItemType Directory -Force -Path $shortcutDir | Out-Null
$shortcut = Join-Path -Path $shortcutDir -ChildPath 'RPP Wallet.lnk'
$wshShell = New-Object -ComObject WScript.Shell
$sc = $wshShell.CreateShortcut($shortcut)
$sc.TargetPath = Join-Path $targetDir 'rpp-wallet-gui.exe'
$sc.WorkingDirectory = $targetDir
$sc.IconLocation = $sc.TargetPath
$sc.Save()

Write-Host "Installed RPP Wallet into $targetDir and added it to the PATH."
Write-Host "A Start Menu shortcut is available under RPP > RPP Wallet."
