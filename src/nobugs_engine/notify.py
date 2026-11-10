"""알림: 사람이 읽는 짧은 요약. 내부 주소·비밀값·기술 응답 코드는 넣지 않는다.

기본은 로컬 수신함(DB)이고, discord_webhook_url을 설정했을 때만 외부로 보낸다.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.request

from .models import Action, Ticket
from .store import Store

LEVEL = {"info": ("ℹ️", "정보"), "warn": ("⚠️", "경고"), "error": ("🚨", "오류")}
RESULT_KO = {
    "applied": "조치 적용", "already_applied": "이미 적용돼 있음", "released": "원복 완료",
    "dry_run": "모의 실행 (실제 조치 없음)", "failed": "조치 실패", "uncertain": "결과 불확실 (확인 필요)",
}
TITLES = {"S1": "로그인 반복 실패(무차별 대입)", "S4": "로그인 실패 뒤 성공(계정 탈취 의심)", "S7": "홈페이지 변조",
          "S8": "웹 스캔 뒤 로그인 시도", "S10": "스캔·로그인·경계 차단 신호 연쇄", "S12": "요청 폭주"}


def format_message(level: str, ticket: Ticket, result: str, actions: list[Action] | None = None,
                   extra: str = "", now: dt.datetime | None = None) -> str:
    icon = LEVEL[level][0]
    kst = ((now or dt.datetime.now(dt.UTC)) + dt.timedelta(hours=9)).strftime("%H:%M:%S")
    title = TITLES.get(ticket.case_id, "")
    head = f"{icon} **[{ticket.case_id}] {title}**" if title else f"{icon} **[{ticket.case_id}]**"
    lines = [head, f"결과: {RESULT_KO.get(result, result)}"]
    if ticket.src_ip:
        lines.append(f"출발지: {ticket.src_ip}")
    if ticket.username:
        lines.append(f"계정: {ticket.username}")
    if ticket.case_id == "S7" and "@" in ticket.group_key:
        asset_id, _, file_key = ticket.group_key.partition("@")
        lines.append(f"자산: {asset_id}")
        lines.append(f"파일: {file_key}")
    checks = []
    for action in actions or []:
        if action.kind in ("boundary_block", "boundary_release"):
            if action.applied_verified:
                checks.append("경계 차단 목록 반영 확인(시뮬레이션, 실제 패킷 차단 아님)")
            continue
        if action.kind in ("file_restore", "file_quarantine"):
            if action.applied_verified:
                checks.append("기준본과 일치 확인됨" if action.kind == "file_restore" else "격리되어 사라짐 확인됨")
            continue
        if action.applied_verified:
            checks.append("계정 잠금 상태 확인됨" if action.kind.startswith("account") else "포털 차단 목록에 반영됨")
        if action.effect_verified is True:
            if action.kind.startswith("account"):
                checks.append("로그인 세션 모두 종료 확인됨" if action.kind == "account_lock" else "계정 복구 확인됨")
            else:
                checks.append("실제 접근 차단 확인됨" if result != "released" else "접근 복구 확인됨")
        elif action.effect_verified is False:
            checks.append("효과 확인 실패")
    if checks:
        lines.append("확인: " + " · ".join(dict.fromkeys(checks)))
    if extra:
        lines.append(extra)
    lines.append(f"— 티켓 {ticket.id} · {kst} KST")
    return "\n".join(lines)


class Notifier:
    def __init__(self, store: Store, discord_webhook_url: str = "") -> None:
        self.store = store
        self.discord = discord_webhook_url

    def send(self, content: str) -> None:
        self.store.add_notification(content)
        if self.discord:
            try:
                request = urllib.request.Request(self.discord, method="POST", data=json.dumps(
                    {"content": content[:1900]}).encode(), headers={"Content-Type": "application/json"})
                urllib.request.urlopen(request, timeout=10).read()
            except OSError:
                pass  # 알림 실패가 대응을 막으면 안 된다
