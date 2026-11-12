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

# 외부 명령(python·pip·npm)은 종료 코드로 성공을 판정한다. Windows PowerShell 5.1은 출력을 파일로 돌리면
# (예: setup.ps1 *> log.txt) 외부 명령의 stderr 안내 문구(pip 새 버전 알림 등)까지 오류로 바꿔 'Stop'에서
# 설치를 멈춘다(실제로 겪음). 반대로 'Stop'만으로는 pip·npm이 실패해도(종료 코드 1) 멈추지 않는다.
function Invoke-Step([string]$What, [scriptblock]$Command) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $saved }
    if ($LASTEXITCODE -ne 0) { throw "$What 실패(종료 코드 $LASTEXITCODE) - 위 출력을 확인하세요." }
}

if (-not (Test-Path .venv)) { Invoke-Step '가상환경 만들기' { python -m venv .venv } }
$py = Join-Path $root '.venv\Scripts\python.exe'
Invoke-Step '파이썬 의존성 설치' { & $py -m pip install -q -e ".[dev]" -c constraints.txt }

if (-not $SkipFrontend) {
    Push-Location web
    try {
        Invoke-Step '프론트 의존성 설치(npm ci)' { npm ci }
        Invoke-Step '프론트 빌드' { npm run build }
    } finally { Pop-Location }
}

$setupArgs = @()
if ($WithWazuh) { $setupArgs += '--with-wazuh' }
if ($SkipDocker) { $setupArgs += '--skip-docker' }
if ($Live) { $setupArgs += '--live' }
$saved = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $py -m nobugs_tools.setup @setupArgs
$setupExit = $LASTEXITCODE
$ErrorActionPreference = $saved

# pfSense syslog 중계기: .env의 NB_SYSLOG_BIND가 루프백이 아니면(연동 설정됨) 백그라운드로 띄운다.
# Docker Desktop이 외부 UDP를 컨테이너로 못 넘겨서, 호스트 중계기가 받아 GELF/TCP로 Graylog에 넣는다.
$bindLine = Select-String -Path (Join-Path $root '.env') -Pattern '^NB_SYSLOG_BIND=(.+)$' -ErrorAction SilentlyContinue
$bind = if ($bindLine) { $bindLine.Matches[0].Groups[1].Value.Trim() } else { '' }
if ($bind -and $bind -notin @('127.0.0.1', '0.0.0.0', 'localhost')) {
    $running = Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*nobugs_tools.syslog_relay*' }
    if ($running) {
        Write-Host "pfSense syslog 중계기 이미 실행 중(PID $($running.ProcessId -join ', ')) - 생략"
    } else {
        $relay = Start-Process -FilePath $py -ArgumentList '-m', 'nobugs_tools.syslog_relay' `
            -WindowStyle Hidden -PassThru
        Write-Host "pfSense syslog 중계기 시작(PID $($relay.Id)): $bind`:1514 -> Graylog GELF/TCP"
    }
} else {
    Write-Host "pfSense syslog 중계기: 생략(.env의 NB_SYSLOG_BIND가 루프백 - 연동 시 VMnet 호스트 IP로 바꾸세요)"
}
exit $setupExit
