"""설정. 환경변수에서 읽고, 테스트에서는 직접 값을 넘긴다."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///instance/portal.sqlite3"
    event_log_path: str = "instance/events.jsonl"
    asset_id: str = "nobugs-portal"
    session_ttl_seconds: int = 4 * 3600
    # 같은 출발지에서 이 시간(초) 안에 로그인 실패가 이 횟수 이상이면 429
    login_rate_limit: int = 20
    login_rate_window_seconds: int = 300
    cookie_secure: bool = False
    gelf_enabled: bool = False
    gelf_host: str = "127.0.0.1"
    gelf_port: int = 12201
    # 대응 API: 키와 허용 대역이 모두 있어야 켜진다(기본은 꺼짐)
    response_api_key: str = ""
    response_allowed_cidrs: tuple[str, ...] = ()
    enable_docs: bool = False
    frontend_dist: str = "web/dist"
    # S7 기준본: 변조 복구 때 이 폴더의 내용으로 되돌린다(instance/, Git 제외)
    baseline_dir: str = "instance/baseline"
    quarantine_dir: str = "instance/quarantine"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        cidrs = tuple(x.strip() for x in e.get("NB_RESPONSE_ALLOWED_CIDRS", "").split(",") if x.strip())
        defaults = cls()
        return cls(
            database_url=e.get("NB_DATABASE_URL", defaults.database_url),
            event_log_path=e.get("NB_EVENT_LOG_PATH", defaults.event_log_path),
            asset_id=e.get("NB_ASSET_ID", defaults.asset_id),
            session_ttl_seconds=int(e.get("NB_SESSION_TTL", defaults.session_ttl_seconds)),
            login_rate_limit=int(e.get("NB_LOGIN_RATE_LIMIT", defaults.login_rate_limit)),
            login_rate_window_seconds=int(e.get("NB_LOGIN_RATE_WINDOW", defaults.login_rate_window_seconds)),
            cookie_secure=_bool(e.get("NB_COOKIE_SECURE"), False),
            gelf_enabled=_bool(e.get("NB_GELF_ENABLED"), False),
            gelf_host=e.get("NB_GELF_HOST", defaults.gelf_host),
            gelf_port=int(e.get("NB_GELF_PORT", defaults.gelf_port)),
            response_api_key=e.get("NB_RESPONSE_API_KEY", ""),
            response_allowed_cidrs=cidrs,
            enable_docs=_bool(e.get("NB_ENABLE_DOCS"), False),
            frontend_dist=e.get("NB_FRONTEND_DIST", defaults.frontend_dist),
            baseline_dir=e.get("NB_BASELINE_DIR", defaults.baseline_dir),
            quarantine_dir=e.get("NB_QUARANTINE_DIR", defaults.quarantine_dir),
        )
