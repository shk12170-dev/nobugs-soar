"""엔진 설정. 환경변수(NB_ENGINE_*, NB_RESPONSE_API_KEY)에서 읽는다."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class EngineSettings:
    database_url: str = "sqlite:///instance/engine.sqlite3"
    engine_key: str = ""                            # Graylog -> 엔진 웹훅 인증 키
    control_url: str = "http://127.0.0.1:5101"      # 포털 대응 API(별도 포트)
    control_key: str = ""                           # 엔진 -> 포털 대응 API 키
    probe_base_url: str = "http://127.0.0.1:5100"   # 효과 확인에 쓰는 일반 포털 주소
    control_timeout: float = 5.0
    release_ttl_seconds: int = 90                   # 조치 후 이 시간이 지나면 자동 원복 대상
    scheduler_interval_seconds: float = 15.0
    scheduler_enabled: bool = True
    # 보호 대상: 어떤 탐지에도 차단하지 않는다(정상 사용자 출발지·관리 대역)
    protected_cidrs: tuple[str, ...] = ("127.0.0.1/32",)
    # 기본은 모의 실행. 실제 조치는 요청이나 설정에서 명시해야 한다.
    default_dry_run: bool = True
    # 경계 시뮬레이터(S10)
    boundary_url: str = "http://127.0.0.1:5300"
    boundary_key: str = ""
    # S4: 실제 잠금은 이 접두사로 시작하는 시험 계정에만 한다(실수로 실제 계정을 잠그지 않도록)
    live_account_prefix: str = "zz_"
    # S12: 서비스 건강 판정
    health_samples: int = 3
    health_interval_seconds: float = 2.0
    health_baseline_ms: float = 200.0
    health_timeout_seconds: float = 5.0
    discord_webhook_url: str = ""                   # 비워 두면 외부로 보내지 않는다(로컬 수신함만)
    # S7: 실제 복구·격리는 이 자산 id에만 한다(실수로 엉뚱한 자산을 건드리지 않도록)
    live_asset_ids: tuple[str, ...] = ("nobugs-portal",)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> EngineSettings:
        e = os.environ if env is None else env
        d = cls()
        listed = [x.strip() for x in e.get("NB_ENGINE_PROTECTED_CIDRS", "").split(",") if x.strip()]
        cidrs = tuple(listed) or d.protected_cidrs
        return cls(
            database_url=e.get("NB_ENGINE_DATABASE_URL", d.database_url),
            engine_key=e.get("NB_ENGINE_KEY", ""),
            control_url=e.get("NB_ENGINE_CONTROL_URL", d.control_url),
            control_key=e.get("NB_RESPONSE_API_KEY", ""),
            probe_base_url=e.get("NB_ENGINE_PROBE_URL", d.probe_base_url),
            control_timeout=float(e.get("NB_ENGINE_CONTROL_TIMEOUT", d.control_timeout)),
            release_ttl_seconds=int(e.get("NB_ENGINE_RELEASE_TTL", d.release_ttl_seconds)),
            scheduler_interval_seconds=float(e.get("NB_ENGINE_SCHEDULER_INTERVAL", d.scheduler_interval_seconds)),
            scheduler_enabled=_bool(e.get("NB_ENGINE_SCHEDULER"), d.scheduler_enabled),
            protected_cidrs=cidrs,
            default_dry_run=_bool(e.get("NB_ENGINE_DRY_RUN"), d.default_dry_run),
            boundary_url=e.get("NB_BOUNDARY_URL", d.boundary_url),
            boundary_key=e.get("NB_BOUNDARY_KEY", ""),
            live_account_prefix=e.get("NB_ENGINE_LIVE_ACCOUNT_PREFIX", d.live_account_prefix),
            health_samples=int(e.get("NB_ENGINE_HEALTH_SAMPLES", d.health_samples)),
            health_interval_seconds=float(e.get("NB_ENGINE_HEALTH_INTERVAL", d.health_interval_seconds)),
            health_baseline_ms=float(e.get("NB_ENGINE_HEALTH_BASELINE_MS", d.health_baseline_ms)),
            health_timeout_seconds=float(e.get("NB_ENGINE_HEALTH_TIMEOUT", d.health_timeout_seconds)),
            discord_webhook_url=e.get("NB_ENGINE_DISCORD_WEBHOOK", ""),
            live_asset_ids=tuple(x.strip() for x in e.get("NB_ENGINE_LIVE_ASSET_IDS", "").split(",") if x.strip())
            or d.live_asset_ids,
        )
