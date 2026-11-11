"""서버 실행기: .env를 읽어 환경변수로 넣은 뒤 포털·대응 API·엔진·경계 시뮬레이터·제어판을 띄운다.

사용: python -m nobugs_tools.run portal     # 일반 포털 http://127.0.0.1:5100
      python -m nobugs_tools.run control    # 포털 대응 API http://127.0.0.1:5101
      python -m nobugs_tools.run engine     # 대응 엔진 http://127.0.0.1:5200
      python -m nobugs_tools.run boundary   # 경계 시뮬레이터 http://127.0.0.1:5300 (S10)
      python -m nobugs_tools.run panel      # 실습 제어판 http://127.0.0.1:5102

서버들은 설정을 환경변수에서만 읽는다. 새 터미널에서 그냥 띄우면 엔진 키가 비어 Graylog 웹훅이 전부 401로
막히고, 포털은 이벤트를 Graylog로 보내지 않는다. 이 실행기가 .env 값을 넣어 그 실수를 막는다.
비밀값은 화면에 찍지 않는다.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

from .graylog import ROOT

_UVICORN = ["-m", "uvicorn", "--factory", "--app-dir", "src", "--host", "127.0.0.1"]
TARGETS: dict[str, tuple[list[str], str]] = {
    "portal": ([*_UVICORN, "nobugs_portal.app:public_factory", "--port", "5100"], "http://127.0.0.1:5100"),
    "control": ([*_UVICORN, "nobugs_portal.control:control_factory", "--port", "5101"], "http://127.0.0.1:5101"),
    "boundary": ([*_UVICORN, "nobugs_boundary.app:boundary_factory", "--port", "5300"], "http://127.0.0.1:5300"),
    "engine": (["-m", "nobugs_engine"], "http://127.0.0.1:5200"),
    "panel": (["-m", "nobugs_tools.panel"], "http://127.0.0.1:5102"),
}
# 이 PC 한 대에서 돌릴 때의 기본값(.env나 터미널에서 따로 정하면 그 값이 이긴다)
LOCAL_DEFAULTS = {"NB_GELF_ENABLED": "true", "NB_RESPONSE_ALLOWED_CIDRS": "127.0.0.0/8"}


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    return values


def build_env(base: Mapping[str, str], file_values: Mapping[str, str]) -> dict[str, str]:
    """우선순위: 터미널에서 직접 정한 값 > .env > 로컬 기본값."""
    env = {**LOCAL_DEFAULTS, **file_values, **base}
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src + (os.pathsep + base["PYTHONPATH"] if base.get("PYTHONPATH") else "")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.run", description="`.env`를 읽어 서버를 띄운다")
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("--env-file", default=str(ROOT / ".env"))
    args = parser.parse_args(argv)
    env_file = Path(args.env_file)
    if not env_file.exists():
        print(f".env가 없습니다: {env_file} - 먼저 `python -m nobugs_tools.make_env`(또는 scripts\\setup.ps1)",
              file=sys.stderr)
        return 2
    cmd, url = TARGETS[args.target]
    env = build_env(os.environ, read_env_file(env_file))
    mode = "실제 조치" if env.get("NB_ENGINE_DRY_RUN", "").lower() in ("false", "0", "no", "off") else "모의 실행"
    extra = f", 엔진 기본 모드: {mode}(Graylog --live 알림은 실제 조치)" if args.target == "engine" else ""
    print(f"{args.target} 시작: {url}{extra} - 끄려면 Ctrl+C", flush=True)
    try:
        return subprocess.call([sys.executable, *cmd], env=env, cwd=ROOT)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
