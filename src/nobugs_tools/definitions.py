"""Graylog 이벤트 정의(탐지 규칙). 규칙의 기준은 docs/BEHAVIOR-SPEC.md의 케이스 표다.

정의를 코드로 만드는 이유: 임계값·창·묶음 단위를 테스트로 고정하고, 설정 도구가 같은 값을 그대로 올리기 위해서다.
"""
from __future__ import annotations

from typing import Any

DEFAULT_STREAM_ID = "000000000000000000000001"      # 모든 메시지 스트림
EVENTS_STREAM_ID = "000000000000000000000002"       # 이벤트 저장 스트림

MINUTE_MS = 60_000


def _template(value: str) -> dict[str, Any]:
    provider = {"type": "template-v1", "template": value, "require_values": True}
    return {"data_type": "string", "providers": [provider]}


def _count_over(threshold: int) -> dict[str, Any]:
    return {"expression": {"expr": ">", "left": {"expr": "number-ref", "ref": "count()"},
                           "right": {"expr": "number", "value": threshold}}}


def s1_login_bruteforce(stream_id: str = DEFAULT_STREAM_ID,
                        notification_ids: list[str] | None = None) -> dict[str, Any]:
    """S1: 같은 계정·출발지의 로그인 실패(401)가 30분 안에 9회 이상(count > 8)이면 발동.

    묶음 단위는 계정+IP이고 같은 키의 재알림은 30분 동안 보내지 않는다.
    """
    return {
        "title": "S1 로그인 무차별 대입 (username+src_ip)",
        "description": "같은 계정·출발지에서 로그인 실패(401)가 30분 안에 9회 이상. 429(속도 제한 응답)는 세지 않는다.",
        "priority": 2,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": "rule:login-bruteforce AND status:401",
            "query_parameters": [],
            "filters": [],
            "streams": [stream_id],
            "group_by": ["username", "src_ip"],
            "series": [{"id": "count()", "type": "count"}],
            "conditions": _count_over(8),
            "search_within_ms": 30 * MINUTE_MS,
            "execute_every_ms": MINUTE_MS,
            "use_cron_scheduling": False,
            "event_limit": 100,
        },
        "field_spec": {
            "username": _template("${source.username}"),
            "src_ip": _template("${source.src_ip}"),
            "case_id": _template("S1"),
        },
        "key_spec": ["username", "src_ip"],
        "notification_settings": {"grace_period_ms": 30 * MINUTE_MS, "backlog_size": 0},
        "notifications": [{"notification_id": n} for n in (notification_ids or [])],
        "storage": [{"type": "persist-to-streams-v1", "streams": [EVENTS_STREAM_ID]}],
    }


ALL_DEFINITIONS = {"S1": s1_login_bruteforce}
