[CmdletBinding()]
param(
    [string]$Version = "local"
)

$ErrorActionPreference = "Stop"

$ScriptsRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptsRoot
Set-Location $ProjectRoot

$DistRoot = Join-Path $ProjectRoot ".artifacts\dist"
$ReleaseRoot = Join-Path $ProjectRoot ".artifacts\release\windows"
$PackageName = "yucedu-vlunhub-scan-$Version-windows-x64"
$StageRoot = Join-Path $ReleaseRoot $PackageName
$ZipPath = Join-Path $ReleaseRoot "$PackageName.zip"
$ExeName = -join @([char]0x9776, [char]0x573A, [char]0x626B, [char]0x63CF, [char]0x52A9, [char]0x624B, [char]0x2E, [char]0x65, [char]0x78, [char]0x65)
$ExePath = Join-Path $DistRoot $ExeName
$LauncherName = -join @([char]0x542F, [char]0x52A8, [char]0x9776, [char]0x573A, [char]0x626B, [char]0x63CF, [char]0x2E, [char]0x76, [char]0x62, [char]0x73)
$LauncherPath = Join-Path $ProjectRoot (Join-Path "launchers" $LauncherName)
$BrowserPath = Join-Path $DistRoot "playwright-browsers"
$PlaywrightRuntimePath = Join-Path $DistRoot "playwright-runtime"

if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Windows EXE is missing; run scripts\build_windows.ps1 first."
}
if (-not (Test-Path -LiteralPath $LauncherPath)) {
    throw "Windows launcher is missing: $LauncherPath"
}
if (-not (Test-Path -LiteralPath $BrowserPath)) {
    throw "External Chromium is missing: $BrowserPath; run scripts\build_windows.ps1 again."
}
if (-not (Test-Path -LiteralPath (Join-Path $PlaywrightRuntimePath "node.exe"))) {
    throw "External Playwright Node driver is missing: $PlaywrightRuntimePath; run scripts\build_windows.ps1 again."
}

Remove-Item -LiteralPath $StageRoot -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $ZipPath -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $StageRoot | Out-Null

Copy-Item -LiteralPath $ExePath -Destination $StageRoot -Force
Copy-Item -LiteralPath $LauncherPath -Destination $StageRoot -Force
Copy-Item -LiteralPath (Join-Path $ProjectRoot "README.md") -Destination $StageRoot -Force
New-Item -ItemType Directory -Force -Path (Join-Path $StageRoot ".github\assets") | Out-Null
Copy-Item -LiteralPath (Join-Path $ProjectRoot ".github\assets\app-preview.png") `
    -Destination (Join-Path $StageRoot ".github\assets\app-preview.png") -Force
Copy-Item -LiteralPath $BrowserPath -Destination $StageRoot -Recurse -Force
Copy-Item -LiteralPath $PlaywrightRuntimePath -Destination $StageRoot -Recurse -Force

$StageEntries = Get-ChildItem -LiteralPath $StageRoot -Force | Select-Object -ExpandProperty FullName
Compress-Archive -Path $StageEntries -DestinationPath $ZipPath -CompressionLevel Optimal
$zipSizeMb = [math]::Round((Get-Item -LiteralPath $ZipPath).Length / 1MB, 1)
Write-Host "Windows release package: $ZipPath ($zipSizeMb MB)"
