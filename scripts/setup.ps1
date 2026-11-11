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
& $py -m pip install -q -e ".[dev]" -c constraints.txt

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
$setupExit = $LASTEXITCODE

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
