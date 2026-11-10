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
        # Graylog -> 대응 엔진 웹훅 인증 키 / 엔진 -> 포털 대응 API 키(서로 다른 값)
        "NB_ENGINE_KEY": secrets.token_urlsafe(24),
        "NB_RESPONSE_API_KEY": secrets.token_urlsafe(24),
        "NB_BOUNDARY_KEY": secrets.token_urlsafe(24),       # 경계 시뮬레이터(S10) 인증 키
        "NB_N8N_USER": "admin",
        "NB_N8N_PASSWORD": secrets.token_urlsafe(18),       # n8n 관리 화면 로그인
        "NB_N8N_WEBHOOK_KEY": secrets.token_urlsafe(24),    # Graylog -> n8n 웹훅 인증 키
        # pfSense syslog를 받을 주소. pfSense는 VMware 망에 있어 루프백으로는 닿지 못하므로,
        # 연동할 때 VMnet 호스트 주소로 바꿔 넣는다(.env는 Git 제외).
        "NB_SYSLOG_BIND": "127.0.0.1",
    }


def add_missing(path: Path) -> list[str]:
    """기존 .env는 건드리지 않고, 새로 필요해진 키만 덧붙인다. 덧붙인 키 이름을 돌려준다."""
    have = {line.split("=", 1)[0] for line in path.read_text(encoding="utf-8").splitlines() if "=" in line}
    new = {k: v for k, v in build_values().items() if k not in have}
    if new:
        with path.open("a", encoding="utf-8") as f:
            f.write("".join(f"{k}={v}\n" for k, v in new.items()))
    return list(new)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--path", default=str(ROOT / ".env"))
    args = parser.parse_args(argv)
    path = Path(args.path)
    if path.exists() and not args.force:
        added = add_missing(path)
        suffix = f" 새 키만 덧붙였습니다: {', '.join(added)}." if added else ""
        print(f"{path} 가 이미 있어 그대로 둡니다(--force로 덮어쓰기).{suffix}")
        return 0
    path.write_text("".join(f"{k}={v}\n" for k, v in build_values().items()), encoding="utf-8")
    print(f"{path} 를 만들었습니다. 비밀번호는 이 파일에만 있습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
