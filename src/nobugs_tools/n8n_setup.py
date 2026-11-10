"""n8n에 자격 증명·워크플로를 반입하고 활성화한다.

자격 증명 JSON은 `.env` 값이 박히므로 파일로 커밋하지 않는다 — 여기서 만들어 컨테이너에 넣고 바로 쓴다.
반입 뒤에는 `publish:workflow`와 컨테이너 재시작이 필요하다(가져온 워크플로는 기본 비활성이다).

사용: python -m nobugs_tools.n8n_setup
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .graylog import load_env

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / "infra" / "n8n" / "workflows"
CREDENTIALS_FILE = ROOT / "infra" / "n8n" / "credentials.local.json"   # gitignore 대상
CONTAINER = "nobugs-soc-n8n-1"
COMPOSE = ROOT / "infra" / "docker-compose.yml"
ENV_FILE = ROOT / ".env"
WORKFLOW_IDS = ("s1-relay",)


class N8nSetupError(RuntimeError):
    pass


def build_credentials(env: dict[str, str]) -> list[dict[str, Any]]:
    """워크플로가 이름으로 참조하는 자격 증명을 .env 값으로 만든다."""
    for key in ("NB_N8N_WEBHOOK_KEY", "NB_ENGINE_KEY"):
        if not env.get(key):
            raise N8nSetupError(f"{key}가 .env에 없습니다(python -m nobugs_tools.make_env 먼저).")
    return [
        {"id": "1", "name": "S1 Webhook Key", "type": "httpHeaderAuth",
         "data": {"name": "X-N8N-Webhook-Key", "value": env["NB_N8N_WEBHOOK_KEY"]}},
        {"id": "2", "name": "Engine Key", "type": "httpHeaderAuth",
         "data": {"name": "X-Engine-Key", "value": env["NB_ENGINE_KEY"]}},
    ]


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT)


def _docker_cp(src: Path, dest: str) -> None:
    if run(["docker", "cp", str(src), f"{CONTAINER}:{dest}"]).returncode != 0:
        raise N8nSetupError(f"docker cp 실패: {src}")


def _n8n(args: list[str]) -> subprocess.CompletedProcess:
    # 컨테이너 안 경로는 Git Bash가 Windows 경로로 바꿔 버리므로 docker exec에 그대로 넘긴다.
    return run(["docker", "exec", CONTAINER, "n8n", *args])


def import_credentials(env: dict[str, str]) -> None:
    CREDENTIALS_FILE.write_text(json.dumps(build_credentials(env), ensure_ascii=False), encoding="utf-8")
    _docker_cp(CREDENTIALS_FILE, "/tmp/credentials.json")
    if _n8n(["import:credentials", "--input=/tmp/credentials.json"]).returncode != 0:
        raise N8nSetupError("자격 증명 반입 실패")


def import_workflows() -> None:
    for path in sorted(WORKFLOW_DIR.glob("*.json")):
        _docker_cp(path, f"/tmp/{path.name}")
        if _n8n(["import:workflow", f"--input=/tmp/{path.name}"]).returncode != 0:
            raise N8nSetupError(f"워크플로 반입 실패: {path.name}")


def publish_and_restart() -> None:
    for workflow_id in WORKFLOW_IDS:
        _n8n(["publish:workflow", f"--id={workflow_id}"])
    # 반입·발행은 DB만 바꾼다 - 돌고 있는 n8n이 워크플로를 다시 읽도록 재시작해야 활성화된다.
    run(["docker", "compose", "-f", str(COMPOSE), "--env-file", str(ENV_FILE), "restart", "n8n"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.n8n_setup")
    parser.add_argument("--skip-restart", action="store_true", help="발행·재시작을 건너뛴다(반입만)")
    args = parser.parse_args(argv)
    try:
        env = load_env()
        import_credentials(env)
        import_workflows()
        if not args.skip_restart:
            publish_and_restart()
        print("n8n 반입 완료. 관리 화면: http://127.0.0.1:5678 (로그인 값은 .env)")
    except N8nSetupError as exc:
        print(f"n8n 설정 실패: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
