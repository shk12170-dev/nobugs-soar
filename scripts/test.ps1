# 로컬 테스트·린트 실행: .\scripts\test.ps1  (처음이면 .venv를 만들고 의존성을 설치한다)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Test-Path .venv)) { python -m venv .venv }
$py = Join-Path $root '.venv\Scripts\python.exe'
& $py -m pip install -q -e ".[dev]"
& $py -m ruff check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $py -m pytest
exit $LASTEXITCODE
