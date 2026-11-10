"""처음부터 전체 스택을 한 번에 올리는 설치 도구(M7). 벤치마크 전제: `.venv`·프론트 빌드는
`scripts/setup.ps1`이 먼저 끝내 둔다(이 모듈은 그 뒤 .env·docker·기준본·Graylog·상태 대조만 한다).

사용: python -m nobugs_tools.setup                  # mongodb+opensearch+graylog만
      python -m nobugs_tools.setup --with-wazuh      # S7용 wazuh-manager+agent도 같이
      python -m nobugs_tools.setup --skip-docker     # 이미 떠 있는 스택에 설정만 다시 올림
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from . import graylog as graylog_tool
from . import make_env

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "infra" / "docker-compose.yml"
ENV_FILE = ROOT / ".env"
BASE_SERVICES = ("mongodb", "opensearch", "graylog")
WAZUH_SERVICES = ("wazuh-manager", "wazuh-agent")


class SetupError(RuntimeError):
    pass


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, **kwargs)


def step_env() -> None:
    """.env가 없으면 만들고, 있으면 새로 필요해진 키만 보충한다(기존 비밀값은 그대로 둔다)."""
    if not ENV_FILE.exists():
        make_env.main(["--path", str(ENV_FILE)])
    else:
        added = make_env.add_missing(ENV_FILE)
        print(f".env가 이미 있어 그대로 둡니다{'(새 키 보충: ' + ', '.join(added) + ')' if added else ''}.")


def step_docker_up(with_wazuh: bool) -> None:
    services = list(BASE_SERVICES) + (list(WAZUH_SERVICES) if with_wazuh else [])
    result = run(["docker", "compose", "-f", str(COMPOSE), "--env-file", str(ENV_FILE), "up", "-d", *services])
    if result.returncode != 0:
        raise SetupError("docker compose up이 실패했습니다. 위 출력을 확인하세요.")


def step_wait_graylog(timeout: int = 240) -> None:
    print("Graylog 준비를 기다립니다...")
    graylog_tool.client_from_env().wait_ready(timeout)
    print("Graylog 준비됨")


def step_seed_baseline() -> bool:
    """지금 web/dist를 S7 기준본으로 저장한다. web/dist가 없으면(프론트 미빌드) 건너뛴다."""
    if not (ROOT / "web" / "dist").is_dir():
        print("web/dist가 없어 기준본 저장을 건너뜁니다(먼저 프론트를 빌드하세요: cd web && npm ci && npm run build).")
        return False
    result = run([sys.executable, "-m", "nobugs_portal.cli", "seed-baseline"])
    return result.returncode == 0


def step_seed_demo() -> bool:
    """빈 DB에만 시연 계정 3개를 만든다. 이미 계정이 있으면 cli.py가 알아서 거절한다(그 메시지가 그대로 보인다).

    출력을 가로채 다시 안 찍는다 - 자식 프로세스가 콘솔에 바로 쓰게 둔다. capture_output으로 받으면 자식의
    실제 출력 인코딩이 이 프로세스를 어떤 셸에서 띄웠는지에 따라 달라져(PowerShell이면 UTF-8, Git Bash면
    cp949인 걸 실제로 겪었다) 고정된 encoding을 넘기면 둘 중 하나에서는 읽기 스레드가 깨진다.
    """
    result = run([sys.executable, "-m", "nobugs_portal.cli", "seed-demo"])
    return result.returncode == 0


def step_graylog_setup(live: bool) -> None:
    client = graylog_tool.client_from_env()
    env = graylog_tool.load_env()
    graylog_tool.setup(client, "http://host.docker.internal:5200/webhook/graylog", env.get("NB_ENGINE_KEY", ""),
                       live)


def _docker_status(name: str) -> str:
    try:
        out = subprocess.run(["docker", "inspect", "--format", "{{.State.Status}}", name], cwd=ROOT,
                             capture_output=True, text=True, timeout=10, encoding="utf-8")
        return out.stdout.strip() or "없음"
    except (subprocess.SubprocessError, OSError):
        return "없음"


def _graylog_reachable(url: str) -> bool:
    try:
        urllib.request.urlopen(url.rstrip("/") + "/api/system/lbstatus", timeout=5).read()
        return True
    except (urllib.error.URLError, OSError):
        return False


def status_report(with_wazuh: bool) -> dict[str, str | bool]:
    """설치가 끝난 뒤 뭐가 떠 있는지 한눈에 보여준다("시작 시 상태 대조")."""
    env = graylog_tool.load_env()
    containers = {f"nobugs-soc-{s}-1": _docker_status(f"nobugs-soc-{s}-1")
                 for s in (list(BASE_SERVICES) + (list(WAZUH_SERVICES) if with_wazuh else []))}
    return {
        "env_file": ENV_FILE.exists(),
        "web_dist": (ROOT / "web" / "dist" / "index.html").is_file(),
        "baseline": (ROOT / "instance" / "baseline").is_dir(),
        "containers": containers,
        "graylog_reachable": _graylog_reachable(env.get("NB_GRAYLOG_URL", "http://127.0.0.1:9100")),
    }


def print_status(status: dict[str, str | bool]) -> None:
    ok = lambda v: "확인" if v else "미확인"  # noqa: E731
    print("\n=== 설치 상태 ===")
    print(f".env: {ok(status['env_file'])}")
    print(f"프론트 빌드(web/dist): {ok(status['web_dist'])}")
    print(f"S7 기준본(instance/baseline): {ok(status['baseline'])}")
    for name, state in status["containers"].items():
        print(f"컨테이너 {name}: {state}")
    print(f"Graylog 응답: {ok(status['graylog_reachable'])}")
    print("\n다음으로 포털·대응 API·엔진을 각자 터미널에서 띄우세요(README '실행' 참고):")
    print("  .\\.venv\\Scripts\\python.exe -m uvicorn nobugs_portal.app:public_factory --factory --port 5100 "
         "--app-dir src")
    print("  .\\.venv\\Scripts\\python.exe -m uvicorn nobugs_portal.control:control_factory --factory --port 5101 "
         "--app-dir src")
    print("  .\\.venv\\Scripts\\python.exe -m nobugs_engine")


def run_setup(with_wazuh: bool = False, skip_docker: bool = False, live: bool = False) -> dict[str, str | bool]:
    step_env()
    if not skip_docker:
        step_docker_up(with_wazuh)
        step_wait_graylog()
    step_seed_baseline()
    step_seed_demo()
    step_graylog_setup(live)
    status = status_report(with_wazuh)
    print_status(status)
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.setup")
    parser.add_argument("--with-wazuh", action="store_true", help="S7용 wazuh-manager+agent도 같이 올린다")
    parser.add_argument("--skip-docker", action="store_true", help="docker compose up을 건너뛴다(이미 떠 있을 때)")
    parser.add_argument("--live", action="store_true", help="Graylog 알림을 실제 조치 모드로 올린다(기본은 모의 실행)")
    args = parser.parse_args(argv)
    try:
        run_setup(with_wazuh=args.with_wazuh, skip_docker=args.skip_docker, live=args.live)
    except SetupError as exc:
        print(f"설치 실패: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
