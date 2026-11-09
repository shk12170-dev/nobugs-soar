"""E2E 시험용 서버: 임시 DB와 임시 이벤트 파일로 실제 포털(프론트 포함)을 띄운다.

시험 전용 계정(담당자·관리자)을 미리 만든다. 비밀번호는 시험용 합성 값이며 실제 계정과 무관하다.
사용: python scripts/e2e_server.py   (환경변수 E2E_PORT, 기본 5199 / 먼저 web/ 에서 npm run build)
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import uvicorn  # noqa: E402

from nobugs_portal import cli  # noqa: E402
from nobugs_portal.app import create_public_app  # noqa: E402
from nobugs_portal.config import Settings  # noqa: E402
from nobugs_portal.db import Database  # noqa: E402

E2E_STAFF = ("staff_e2e", "E2e-Staff-Passw0rd-1")
E2E_ADMIN = ("admin_e2e", "E2e-Admin-Passw0rd-1")


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="nobugs-e2e-"))
    settings = Settings(database_url=f"sqlite:///{(work / 'e2e.db').as_posix()}",
                        event_log_path=str(work / "events.jsonl"),
                        frontend_dist=str(ROOT / "web" / "dist"), login_rate_limit=1000)
    db = Database(settings.database_url)
    db.create_all()
    cli.create_user(db, E2E_STAFF[0], "시험 담당자", "staff", E2E_STAFF[1])
    cli.create_user(db, E2E_ADMIN[0], "시험 관리자", "admin", E2E_ADMIN[1])
    db.dispose()
    uvicorn.run(create_public_app(settings), host="127.0.0.1", port=int(os.environ.get("E2E_PORT", "5199")),
                log_level="warning")


if __name__ == "__main__":
    main()
