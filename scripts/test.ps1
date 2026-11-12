# 로컬 테스트·린트 실행: .\scripts\test.ps1  (처음이면 .venv를 만들고 의존성을 설치한다)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# 외부 명령은 종료 코드로 판정한다(이유는 setup.ps1의 Invoke-Step 설명 참고)
function Invoke-Step([string]$What, [scriptblock]$Command) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $saved }
    if ($LASTEXITCODE -ne 0) { Write-Host "$What 실패(종료 코드 $LASTEXITCODE)"; exit $LASTEXITCODE }
}

if (-not (Test-Path .venv)) { Invoke-Step '가상환경 만들기' { python -m venv .venv } }
$py = Join-Path $root '.venv\Scripts\python.exe'
Invoke-Step '파이썬 의존성 설치' { & $py -m pip install -q -e ".[dev]" -c constraints.txt }
Invoke-Step '린트(ruff)' { & $py -m ruff check . }
Invoke-Step '테스트(pytest)' { & $py -m pytest }
exit 0
