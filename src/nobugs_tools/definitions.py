"""Graylog 이벤트 정의(탐지 규칙). 규칙의 기준은 docs/BEHAVIOR-SPEC.md의 케이스 표다.

정의를 코드로 만드는 이유: 임계값·창·묶음 단위를 테스트로 고정하고, 설정 도구가 같은 값을 그대로 올리기 위해서다.
"""
from __future__ import annotations

from typing import Any

DEFAULT_STREAM_ID = "000000000000000000000001"      # 모든 메시지 스트림
EVENTS_STREAM_ID = "000000000000000000000002"       # 이벤트 저장 스트림

MINUTE_MS = 60_000


def _template(value: str, require: bool = True) -> dict[str, Any]:
    provider = {"type": "template-v1", "template": value, "require_values": require}
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


def _and(*parts: dict[str, Any]) -> dict[str, Any]:
    expr = parts[0]["expression"]
    for part in parts[1:]:
        expr = {"expr": "&&", "left": expr, "right": part["expression"]}
    return {"expression": expr}


def _distinct_at_least(series: str, minimum: int) -> dict[str, Any]:
    return {"expression": {"expr": ">=", "left": {"expr": "number-ref", "ref": series},
                           "right": {"expr": "number", "value": minimum}}}


def _definition(title: str, description: str, case: str, query: str, group_by: list[str],
                series: list[dict[str, Any]], conditions: dict[str, Any], window_min: float, every_ms: int,
                grace_min: float, stream_id: str, notification_ids: list[str] | None,
                extra_fields: dict[str, Any] | None = None, require_src_ip: bool = True) -> dict[str, Any]:
    fields = {"src_ip": _template("${source.src_ip}", require_src_ip), "case_id": _template(case),
              "username": _template("${source.username}") if "username" in group_by else _template("-")}
    fields.update(extra_fields or {})
    return {
        "title": title, "description": description, "priority": 2, "alert": True,
        "config": {"type": "aggregation-v1", "query": query, "query_parameters": [], "filters": [],
                   "streams": [stream_id], "group_by": group_by, "series": series, "conditions": conditions,
                   "search_within_ms": int(window_min * MINUTE_MS), "execute_every_ms": every_ms,
                   "use_cron_scheduling": False, "event_limit": 100},
        "field_spec": fields,
        "key_spec": group_by,
        "notification_settings": {"grace_period_ms": int(grace_min * MINUTE_MS), "backlog_size": 0},
        "notifications": [{"notification_id": n} for n in (notification_ids or [])],
        "storage": [{"type": "persist-to-streams-v1", "streams": [EVENTS_STREAM_ID]}],
    }


_COUNT = {"id": "count()", "type": "count"}
_KINDS = {"id": "card(rule)", "type": "card", "field": "rule"}
FAILED_LOGIN = "(rule:login-bruteforce AND status:401)"


def s4_login_failure_then_success(stream_id: str = DEFAULT_STREAM_ID,
                                  notification_ids: list[str] | None = None) -> dict[str, Any]:
    """S4: 같은 계정·출발지에서 실패와 성공이 모두 있고 합이 6회 이상(10분)이면 발동(계정 탈취 의심)."""
    return _definition(
        "S4 로그인 실패 뒤 성공 (username+src_ip)",
        "같은 계정·출발지에서 로그인 실패(401)와 성공이 모두 있고 합이 10분 안에 6회 이상.", "S4",
        f"{FAILED_LOGIN} OR rule:login-success", ["username", "src_ip"], [_COUNT, _KINDS],
        _and(_count_over(5), _distinct_at_least("card(rule)", 2)), 10, MINUTE_MS, 10, stream_id, notification_ids)


def s7_tamper_then_access(stream_id: str = DEFAULT_STREAM_ID,
                          notification_ids: list[str] | None = None) -> dict[str, Any]:
    """S7: 같은 자산·파일 키에 변조 신호(Wazuh FIM, nobugs_tools.wazuh_bridge가 중계)와 방문자의 정상 접근(2xx)이
    모두 있으면(10분) 발동. 기준본과 같은 변경은 bridge가 애초에 보내지 않는다(여기서는 더 거르지 않는다)."""
    return _definition(
        "S7 홈페이지 변조 (asset_id+file_key)",
        "같은 자산·파일에 변조 신호와 방문자 접근(2xx)이 모두 10분 안에 있음.", "S7",
        "rule:tamper-signal OR (rule:file-access AND status:200)", ["asset_id", "file_key"], [_COUNT, _KINDS],
        _and(_count_over(1), _distinct_at_least("card(rule)", 2)), 10, 30_000, 10, stream_id, notification_ids,
        extra_fields={"asset_id": _template("${source.asset_id}"), "file_key": _template("${source.file_key}")},
        require_src_ip=False)


def s8_scan_then_login(stream_id: str = DEFAULT_STREAM_ID,
                       notification_ids: list[str] | None = None) -> dict[str, Any]:
    """S8: 같은 출발지에서 웹 스캔(404)과 로그인 실패가 모두 있으면(15분) 발동. 스캔은 3건 이상이어야 한다."""
    return _definition(
        "S8 웹 스캔 뒤 로그인 시도 (src_ip)",
        "같은 출발지에서 웹 스캔(404)과 로그인 실패(401)가 모두 15분 안에 있고 합이 5회 이상.", "S8",
        f"rule:web-scan OR {FAILED_LOGIN}", ["src_ip"], [_COUNT, _KINDS],
        _and(_count_over(4), _distinct_at_least("card(rule)", 2)), 15, MINUTE_MS, 15, stream_id, notification_ids)


def s10_three_layer(stream_id: str = DEFAULT_STREAM_ID,
                    notification_ids: list[str] | None = None) -> dict[str, Any]:
    """S10: S8에 경계 차단 신호(boundary-block)까지 더해 세 종류가 모두 있으면(15분) 발동."""
    return _definition(
        "S10 스캔·로그인·경계 신호 연쇄 (src_ip)",
        "같은 출발지에서 웹 스캔·로그인 실패·경계 차단 신호 세 종류가 모두 15분 안에 있음.", "S10",
        f"rule:web-scan OR {FAILED_LOGIN} OR rule:boundary-block", ["src_ip"], [_COUNT, _KINDS],
        _and(_count_over(4), _distinct_at_least("card(rule)", 3)), 15, MINUTE_MS, 15, stream_id, notification_ids)


def s12_request_flood(stream_id: str = DEFAULT_STREAM_ID,
                      notification_ids: list[str] | None = None) -> dict[str, Any]:
    """S12: 같은 출발지의 요청이 1분에 94건을 넘으면 발동. 차단 여부는 엔진이 서비스 상태를 보고 정한다."""
    return _definition(
        "S12 요청 폭주 (src_ip)", "같은 출발지의 요청이 1분 안에 94건 초과. 대응은 서비스가 실제로 느려졌을 때만.",
        "S12", "rule:request-observed", ["src_ip"], [_COUNT], _count_over(94), 1, 30_000, 5, stream_id,
        notification_ids)


def engine_notification(url: str, key: str, live: bool = False) -> dict[str, Any]:
    """Graylog -> 대응 엔진 웹훅 알림. live=False면 본문에 dry_run:true를 실어 모의 실행으로 보낸다."""
    body = ('{"event_id":"${event.id}","case_id":"${event.fields.case_id}","src_ip":"${event.fields.src_ip}",'
            '"username":"${event.fields.username}","asset_id":"${event.fields.asset_id}",'
            '"file_key":"${event.fields.file_key}","condition_met_at":"${event.timestamp}",'
            '"detected_at":"${event.timestamp_processing}","dry_run":' + ("false" if live else "true") + "}")
    return {
        "title": "nobugs 대응 엔진 웹훅",
        "description": "탐지 이벤트를 대응 엔진으로 보낸다. 인증은 X-Engine-Key 헤더.",
        "config": {"type": "http-notification-v2", "url": url, "method": "POST", "content_type": "JSON",
                   "time_zone": "UTC", "headers": f"X-Engine-Key: {key}", "basic_auth": None,
                   "api_key_as_header": False, "api_key": "", "api_secret": None, "skip_tls_verification": False,
                   "body_template": body},
    }


ALL_DEFINITIONS = {"S1": s1_login_bruteforce, "S4": s4_login_failure_then_success, "S7": s7_tamper_then_access,
                   "S8": s8_scan_then_login, "S10": s10_three_layer, "S12": s12_request_flood}
