"""`.env`를 만든다: 무작위 비밀값 생성. 비밀번호는 콘솔에 출력하지 않고 .env에만 둔다(Git 제외).

이미 .env가 있으면 건드리지 않는다(--force로만 덮어쓴다).
사용: python -m nobugs_tools.make_env
"""
from __future__ import annotations

import argparse
import hashlib
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def build_values() -> dict[str, str]:
    admin_password = secrets.token_urlsafe(18)
    return {
        "NB_OPENSEARCH_PASSWORD": "Os!" + secrets.token_hex(8) + "Aa1",
        "NB_GRAYLOG_SECRET": secrets.token_hex(32),
        "NB_GRAYLOG_ROOT_SHA2": hashlib.sha256(admin_password.encode()).hexdigest(),
        # 설정 도구가 Graylog API를 부를 때 쓰는 관리자 비밀번호(로컬 개발용, .env는 Git 제외)
        "NB_GRAYLOG_ADMIN_PASSWORD": admin_password,
        "NB_GRAYLOG_URL": "http://127.0.0.1:9100",
        "NB_GELF_PORT": "12301",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--path", default=str(ROOT / ".env"))
    args = parser.parse_args(argv)
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{path} 가 이미 있어 그대로 둡니다(--force로 덮어쓰기).")
        return 0
    path.write_text("".join(f"{k}={v}\n" for k, v in build_values().items()), encoding="utf-8")
    print(f"{path} 를 만들었습니다. 비밀번호는 이 파일에만 있습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
