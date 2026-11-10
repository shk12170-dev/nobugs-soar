# 처음부터 전체 스택을 한 번에 올린다: .\scripts\setup.ps1 [-WithWazuh] [-SkipFrontend] [-SkipDocker] [-Live]
param(
    [switch]$WithWazuh,
    [switch]$SkipFrontend,
    [switch]$SkipDocker,
    [switch]$Live
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path .venv)) { python -m venv .venv }
$py = Join-Path $root '.venv\Scripts\python.exe'
& $py -m pip install -q -e ".[dev]"

if (-not $SkipFrontend) {
    Push-Location web
    npm ci
    npm run build
    Pop-Location
}

$setupArgs = @()
if ($WithWazuh) { $setupArgs += '--with-wazuh' }
if ($SkipDocker) { $setupArgs += '--skip-docker' }
if ($Live) { $setupArgs += '--live' }
& $py -m nobugs_tools.setup @setupArgs
exit $LASTEXITCODE
