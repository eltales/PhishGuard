# Builds phishguard.xpi for installation in Thunderbird.
# Run from the project directory: .\build.ps1

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$xpi = Join-Path $root "phishguard.xpi"
$zip = Join-Path $root "phishguard.zip"

if (Test-Path $xpi) { Remove-Item $xpi -Force }
if (Test-Path $zip) { Remove-Item $zip -Force }

Compress-Archive -Path (Join-Path $root "manifest.json"), (Join-Path $root "src") -DestinationPath $zip -Force
Rename-Item $zip $xpi

Write-Host "Built: $xpi"
