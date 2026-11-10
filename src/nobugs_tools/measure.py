"""케이스별 N회 반복 측정: 공격 → 효과 확인까지 걸린 시간을 재고 표로 남긴다(M7).

회차마다 계정·출발지를 다르게 써서 서로 섞이지 않게 한다(S7은 기준본 파일 키를 돌려 쓴다).
실제 포털·대응 API·엔진·Graylog가 떠 있어야 하고, S7은 실제 Wazuh 매니저+에이전트+bridge도 필요하다.

사용: python -m nobugs_tools.measure --case S1 --rounds 5
      python -m nobugs_tools.measure --all --rounds 5 --out docs/MEASUREMENTS.md
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

from . import attacks

PORTAL_BASE = "http://127.0.0.1:5100"
ENGINE_BASE = "http://127.0.0.1:5200"


def _engine_call(engine_base: str, method: str, path: str, engine_key: str = "",
                 body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if engine_key:
        headers["X-Engine-Key"] = engine_key
    request = urllib.request.Request(engine_base + path, method=method, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _tickets(engine_base: str) -> list[dict[str, Any]]:
    return _engine_call(engine_base, "GET", "/api/v1/tickets?limit=200")["data"]["items"]


def _created_at(ticket: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(ticket["created_at"].rstrip("Z")).replace(tzinfo=UTC)


def poll_until(engine_base: str, case: str, group_key: str, terminal: set[str], timeout: float,
              interval: float = 1.0, since: datetime | None = None) -> dict[str, Any] | None:
    """since 이후 새로 생긴 group_key 티켓이 terminal 상태 중 하나에 들어갈 때까지 기다린다.

    since 없이 group_key만 보면, 같은 키를 돌려 쓰는 이전 측정 회차의 오래된 티켓을 이번 회차 결과로
    잘못 집어낼 수 있다(측정을 반복할 때 실제로 겪은 문제).
    """
    deadline = time.monotonic() + timeout
    while True:
        for t in _tickets(engine_base):
            if (t["case_id"] == case and t["group_key"] == group_key and t["status"] in terminal
                   and (since is None or _created_at(t) >= since)):
                return t
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


def confirm_no_ticket(engine_base: str, case: str, group_key: str, wait: float, interval: float = 1.0,
                      since: datetime | None = None) -> bool:
    """wait 동안 since 이후 group_key로 생긴 티켓이 하나도 없으면 True(무해한 신호는 조치하지 않는 설계 확인)."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if any(t["case_id"] == case and t["group_key"] == group_key and (since is None or _created_at(t) >= since)
              for t in _tickets(engine_base)):
            return False
        time.sleep(interval)
    return not any(t["case_id"] == case and t["group_key"] == group_key and (since is None or _created_at(t) >= since)
                  for t in _tickets(engine_base))


def register_test_account(portal_base: str, username: str, password: str) -> None:
    """측정용 계정을 가입시킨다(zz_ 접두, 이미 있으면 그냥 넘어간다)."""
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    me = json.loads(opener.open(portal_base + "/api/v1/auth/me", timeout=10).read())
    csrf = me["data"]["csrf_token"]
    body = json.dumps({"username": username, "display_name": "측정용", "password": password}).encode()
    request = urllib.request.Request(portal_base + "/api/v1/auth/register", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-CSRF-Token": csrf})
    try:
        opener.open(request, timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code != 409:   # 이미 가입됨(재실행) 외에는 그대로 올린다
            raise


@dataclass
class Round:
    case: str
    round: int
    group_key: str
    status: str
    seconds: float | None
    ok: bool
    detail: str = ""


def _s1_round(i: int, *, base: str, engine: str, timeout: float = 90, salt: int = 0, **_: Any) -> Round:
    # Graylog가 S1 정의를 60초마다 평가한다(definitions.py) - 그보다 짧은 시간제한은 타이밍에 따라
    # 실제로는 성공할 호출도 "timeout"으로 잘못 보고한다.
    # salt는 도구를 다시 돌릴 때마다 바뀐다 - 같은 IP를 또 쓰면 포털의 로그인 횟수 제한에 걸려
    # (출발지당 5분에 20회) 실제로는 통과할 시도도 429로 막혀 버린다(반복 측정 중 실제로 겪은 문제).
    user, src = f"zz_measure_s1_{salt}_{i}", f"127.21.{salt}.{i}"
    group_key = f"{user}@{src}"
    since, t0 = datetime.now(UTC), time.monotonic()
    attacks.s1_login_bruteforce(base, username=user, count=10, source=src, interval=0.2)
    ticket = poll_until(engine, "S1", group_key, {"verified", "restored"}, timeout=timeout, since=since)
    seconds = time.monotonic() - t0
    return Round("S1", i, group_key, ticket["status"] if ticket else "timeout", seconds, ticket is not None)


def _s4_round(i: int, *, base: str, engine: str, timeout: float = 90, salt: int = 0, **_: Any) -> Round:
    user, src = f"zz_measure_s4_{salt}_{i}", f"127.22.{salt}.{i}"
    password = f"측정비번-{salt}-{i}-abcdefgh"
    group_key = f"{user}@{src}"
    register_test_account(base, user, password)
    since, t0 = datetime.now(UTC), time.monotonic()
    attacks.s4_failure_then_success(base, username=user, password=password, failures=5, source=src, interval=0.2)
    ticket = poll_until(engine, "S4", group_key, {"verified", "restored"}, timeout=timeout, since=since)
    seconds = time.monotonic() - t0
    return Round("S4", i, group_key, ticket["status"] if ticket else "timeout", seconds, ticket is not None)


def _s8_round(i: int, *, base: str, engine: str, timeout: float = 90, salt: int = 0, **_: Any) -> Round:
    src = f"127.23.{salt}.{i}"
    since, t0 = datetime.now(UTC), time.monotonic()
    attacks.s8_scan_then_login(base, username=f"zz_measure_s8_{salt}_{i}", source=src, interval=0.1)
    ticket = poll_until(engine, "S8", src, {"verified", "restored"}, timeout=timeout, since=since)
    seconds = time.monotonic() - t0
    return Round("S8", i, src, ticket["status"] if ticket else "timeout", seconds, ticket is not None)


def _s10_round(i: int, *, base: str, engine: str, gelf_port: int, timeout: float = 90, salt: int = 0,
              **_: Any) -> Round:
    src = f"127.24.{salt}.{i}"
    since, t0 = datetime.now(UTC), time.monotonic()
    attacks.s10_three_layer(base, source=src, gelf_port=gelf_port, interval=0.1)
    ticket = poll_until(engine, "S10", src, {"verified", "restored"}, timeout=timeout, since=since)
    seconds = time.monotonic() - t0
    return Round("S10", i, src, ticket["status"] if ticket else "timeout", seconds, ticket is not None)


def _s12_round(i: int, *, base: str, engine: str, wait: float = 40, salt: int = 0, **_: Any) -> Round:
    src = f"127.25.{salt}.{i}"
    since, t0 = datetime.now(UTC), time.monotonic()
    attacks.s12_request_burst(base, requests=120, source=src)
    ok = confirm_no_ticket(engine, "S12", src, wait=wait, since=since)
    seconds = time.monotonic() - t0
    return Round("S12", i, src, "no_action" if ok else "unexpected_ticket", seconds, ok,
                detail="무해한 폭주는 차단하지 않는 설계 확인")


def _s7_round(i: int, *, base: str, engine: str, web_root: str, baseline_dir: str, asset_id: str,
             timeout: float = 90, salt: int = 0, **_: Any) -> Round:
    from nobugs_portal import baseline

    keys = sorted(baseline.baseline_keys(baseline_dir))
    if not keys:
        return Round("S7", i, "-", "no_baseline", None, False, detail="기준본이 없음(seed-baseline 먼저)")
    file_key = keys[(i - 1) % len(keys)]
    group_key = f"{asset_id}@{file_key}"
    since, t0 = datetime.now(UTC), time.monotonic()
    attacks.s7_deface(base, web_root, file_key, source=f"127.26.{salt}.{i}")
    ticket = poll_until(engine, "S7", group_key, {"restored", "quarantined"}, timeout=timeout, interval=2.0,
                       since=since)
    seconds = time.monotonic() - t0
    return Round("S7", i, group_key, ticket["status"] if ticket else "timeout", seconds, ticket is not None)


ROUND_FUNCS: dict[str, Callable[..., Round]] = {"S1": _s1_round, "S4": _s4_round, "S7": _s7_round,
                                                "S8": _s8_round, "S10": _s10_round, "S12": _s12_round}


def measure_case(case: str, rounds: int, **kwargs: Any) -> list[Round]:
    fn = ROUND_FUNCS[case]
    rows = []
    for i in range(1, rounds + 1):
        try:
            rows.append(fn(i, **kwargs))
        except Exception as exc:  # noqa: BLE001 - 한 회차가 터져도 나머지 회차·케이스는 계속 돈다
            rows.append(Round(case, i, "-", "error", None, False, detail=str(exc)[:200]))
    return rows


def to_markdown(all_rounds: dict[str, list[Round]]) -> str:
    lines = ["| 케이스 | 회차 | 묶음 키 | 상태 | 걸린 시간(s) | 결과 |", "| --- | --- | --- | --- | --- | --- |"]
    for case, rows in all_rounds.items():
        for r in rows:
            seconds = f"{r.seconds:.1f}" if r.seconds is not None else "-"
            lines.append(f"| {case} | {r.round} | {r.group_key} | {r.status} | {seconds} | "
                        f"{'확인' if r.ok else '미확인'}{(' - ' + r.detail) if r.detail else ''} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.measure")
    parser.add_argument("--case", help="쉼표로 구분한 케이스 목록(예: S1,S4). --all과 함께 쓰지 않는다")
    parser.add_argument("--all", action="store_true", help="모든 케이스(S1,S4,S7,S8,S10,S12)")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--base", default=PORTAL_BASE)
    parser.add_argument("--engine", default=ENGINE_BASE)
    parser.add_argument("--web-root", default="web/dist")
    parser.add_argument("--baseline-dir", default="instance/baseline")
    parser.add_argument("--asset-id", default="nobugs-portal")
    parser.add_argument("--gelf-port", type=int, default=12301)
    parser.add_argument("--out", help="마크다운 표를 저장할 경로(없으면 화면에만 출력)")
    parser.add_argument("--json", help="원본 결과를 저장할 JSON 경로")
    parser.add_argument("--salt", type=int, default=int(time.time()) % 200,
                        help="출발지 IP 대역을 바꿔 쓰는 값. 기본은 실행 시각 기준으로 매번 바뀐다 - 같은 값으로 "
                             "다시 돌리면 이전 회차와 같은 IP를 또 써서 로그인 횟수 제한에 걸릴 수 있다")
    args = parser.parse_args(argv)

    cases = list(ROUND_FUNCS) if args.all else [c.strip().upper() for c in (args.case or "").split(",") if c.strip()]
    if not cases:
        parser.error("--case 또는 --all 중 하나는 있어야 합니다")

    kwargs = {"base": args.base, "engine": args.engine, "web_root": args.web_root,
             "baseline_dir": args.baseline_dir, "asset_id": args.asset_id, "gelf_port": args.gelf_port,
             "salt": args.salt}
    print(f"salt={args.salt} (출발지 IP 대역에 씀)")
    all_rounds: dict[str, list[Round]] = {}
    for case in cases:
        if case not in ROUND_FUNCS:
            parser.error(f"알 수 없는 케이스: {case}")
        print(f"{case}: {args.rounds}회 측정 시작")
        rows = measure_case(case, args.rounds, **kwargs)
        all_rounds[case] = rows
        for r in rows:
            print(f"  회차 {r.round}: {r.status} ({r.seconds:.1f}s)" if r.seconds is not None else
                 f"  회차 {r.round}: {r.status}")

    table = to_markdown(all_rounds)
    print(table)
    if args.out:
        Path(args.out).write_text(table, encoding="utf-8")
        print(f"표를 {args.out}에 저장했습니다")
    if args.json:
        payload = {case: [asdict(r) for r in rows] for case, rows in all_rounds.items()}
        Path(args.json).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"원본 결과를 {args.json}에 저장했습니다")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
