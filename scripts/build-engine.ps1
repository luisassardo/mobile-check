# Build the read-only scan engine into a single self-contained .exe so the
# Windows app needs NO system Python. Output goes where tauri.release.conf.json
# expects it (src-tauri\engine-dist\mobile-check-engine.exe).
#
# Run from the project root (CI does this) BEFORE `npm run tauri build`.
# Requires: python on PATH with pyinstaller + fpdf2
#   pip install pyinstaller fpdf2
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$out = "src-tauri\engine-dist"
Write-Host "==> Building engine .exe with PyInstaller..."
Remove-Item -Recurse -Force "build", $out -ErrorAction SilentlyContinue
Get-ChildItem -Filter *.spec -ErrorAction SilentlyContinue | Remove-Item -Force

python -m PyInstaller `
  --onefile `
  --name mobile-check-engine `
  --distpath $out `
  --workpath build\pyinstaller `
  --specpath build `
  --paths . `
  --add-data "..\engine\data;engine\data" `
  scripts\engine_entry.py

Write-Host "==> Smoke test (expect detection JSON on stdout)..."
& "$out\mobile-check-engine.exe" --detect | Select-Object -First 1
Write-Host "OK: engine at $out\mobile-check-engine.exe"
