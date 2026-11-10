"""대응 엔진 핵심 로직(M4: S1). 규칙은 docs/BEHAVIOR-SPEC.md 4절의 안전 규칙을 따른다.

1 기본은 모의 실행  2 보호 대상은 차단하지 않음  3 변경 호출은 멱등 키, 불확실한 결과는 재조회로 대조
4 (케이스, 키)당 열린 티켓 1개, 같은 IP를 쓰는 티켓이 여럿이어도 원복이 교착되지 않음
5 자동 원복은 TTL 경과 후에만, 효과를 확인하고 티켓에 남김
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import EngineSettings
from .models import Action, Ticket, utcnow
from .notify import Notifier, format_message
from .portal import PortalControl, PortalError, PortalUncertain
from .probe import EffectProbe
from .store import Store


class Detection(BaseModel):
    """Graylog 알림이 보내는 탐지 이벤트."""

    event_id: str = Field(min_length=1, max_length=100)
    case_id: str = Field(min_length=1, max_length=10)
    src_ip: str = Field(max_length=45)
    username: str | None = Field(default=None, max_length=40)
    count: int | None = None
    condition_met_at: str | None = None
    detected_at: str | None = None
    dry_run: bool | None = None


@dataclass(frozen=True)
class CaseSpec:
    title: str

    def group_key(self, d: Detection) -> str:
        return f"{d.username or '-'}@{d.src_ip}"


CASES: dict[str, CaseSpec] = {"S1": CaseSpec("로그인 반복 실패(무차별 대입)")}


def parse_time(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(dt.UTC).replace(tzinfo=None) if parsed.tzinfo else parsed


class Engine:
    def __init__(self, settings: EngineSettings, store: Store, portal: PortalControl, probe: EffectProbe,
                 notifier: Notifier, clock: Callable[[], dt.datetime] = utcnow) -> None:
        self.settings, self.store, self.portal, self.probe, self.notifier, self.clock = (
            settings, store, portal, probe, notifier, clock)
        store.clock = clock
        self._protected = [ipaddress.ip_network(c, strict=False) for c in settings.protected_cidrs]

    # ---- 탐지 처리 ----
    def is_protected(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._protected)

    def handle(self, d: Detection) -> dict:
        spec = CASES.get(d.case_id)
        if spec is None:
            return {"verdict": "unsupported_case", "case_id": d.case_id}
        try:
            ip = str(ipaddress.ip_address(d.src_ip))
        except ValueError:
            return {"verdict": "invalid_input", "detail": "src_ip"}
        if self.is_protected(ip):
            return {"verdict": "protected_source", "src_ip": ip, "no_action": True}
        dry_run = self.settings.default_dry_run if d.dry_run is None else d.dry_run
        with self.store.session() as s:
            self._start_new_round_if_restored(s, d.case_id, spec.group_key(d))
            ticket, created = self.store.open_or_get(
                s, d.case_id, spec.group_key(d), src_ip=ip, username=d.username,
                condition_met_at=parse_time(d.condition_met_at), detected_at=parse_time(d.detected_at))
            if d.event_id not in ticket.event_ids:
                ticket.event_ids = [*ticket.event_ids, d.event_id]
                s.commit()
            if not created and self._already_handled(s, ticket, dry_run):
                return {"verdict": "duplicate", "ticket_id": ticket.id, "status": ticket.status}
            if dry_run:
                action = self.store.add_action(s, ticket, kind="ip_block", target=ip, result="dry_run",
                                               detail="모의 실행: 포털을 호출하지 않았다", finished_at=self.clock())
                self.notifier.send(format_message("warn", ticket, "dry_run", [action], now=self._aware()))
                return {"verdict": "dry_run", "ticket_id": ticket.id, "status": ticket.status}
            return self._apply_block(s, ticket, ip)

    def _start_new_round_if_restored(self, s: Session, case_id: str, group_key: str) -> None:
        """원복이 끝난 티켓(닫히기 전)에 같은 대상의 새 탐지가 오면, 그 티켓을 종료하고 새 라운드를 연다.

        원복된 티켓은 효력이 남은 조치가 없으므로 닫아도 살아 있는 차단을 가리지 않는다.
        """
        existing = s.scalar(select(Ticket).where(Ticket.case_id == case_id, Ticket.group_key == group_key,
                                                 Ticket.status == "restored"))
        if existing is not None:
            self.store.close(s, existing.id, "자동 종료: 원복 뒤 같은 대상에서 새 탐지가 발생해 새 사건으로 처리")

    def _already_handled(self, s: Session, ticket: Ticket, dry_run: bool) -> bool:
        actions = self.store.actions_of(s, ticket.id)
        if dry_run:
            return bool(actions)
        return any(a.active or a.result in ("applied", "already_applied") for a in actions)

    def _aware(self) -> dt.datetime:
        return self.clock().replace(tzinfo=dt.UTC)

    def _apply_block(self, s: Session, ticket: Ticket, ip: str) -> dict:
        requested = self.clock()
        result, detail, uncertain = "applied", "", False
        try:
            response = self.portal.block_ip(ip, f"{ticket.id}-block-{ip}")
            result = "applied" if response.get("changed") else "already_applied"
        except PortalError as exc:
            return self._failed(s, ticket, ip, "failed", f"포털이 거절함: {exc}", requested)
        except PortalUncertain as exc:
            uncertain, detail = True, str(exc)
        listed = self._listed(ip)
        if uncertain:
            # 불확실한 결과: 실제 차단 목록을 다시 보고 사실대로 기록한다(자동 재시도 없음)
            if listed:
                result, detail = "applied", detail + " → 재조회로 적용 확인"
            else:
                return self._failed(s, ticket, ip, "uncertain", detail + " → 재조회에서도 확인 불가", requested)
        effect = self.probe.is_blocked(ip)
        action = self.store.add_action(
            s, ticket, kind="ip_block", target=ip, result=result, applied_verified=listed, effect_verified=effect,
            active=True, detail=detail, requested_at=requested, finished_at=self.clock(),
            effect_at=self.clock() if effect is not None else None)
        self.store.advance(s, ticket, "verified" if effect else "responding")
        self.notifier.send(format_message("warn", ticket, result, [action], now=self._aware()))
        return {"verdict": "responded", "ticket_id": ticket.id, "status": ticket.status, "result": result,
                "applied_verified": listed, "effect_verified": effect}

    def _failed(self, s: Session, ticket: Ticket, ip: str, result: str, detail: str, requested: dt.datetime) -> dict:
        action = self.store.add_action(s, ticket, kind="ip_block", target=ip, result=result, applied_verified=False,
                                       active=False, detail=detail[:300], requested_at=requested,
                                       finished_at=self.clock())
        self.notifier.send(format_message("error", ticket, result, [action], now=self._aware()))
        return {"verdict": "failed", "ticket_id": ticket.id, "status": ticket.status, "result": result}

    def _listed(self, ip: str) -> bool | None:
        try:
            return ip in self.portal.blocked_ips()
        except (PortalError, PortalUncertain):
            return None

    # ---- 자동 원복 ----
    def release_due(self) -> list[str]:
        """TTL이 지난 티켓의 차단을 푼다. 같은 IP를 쓰는 티켓은 모두 TTL이 지났을 때 한꺼번에 푼다."""
        released: list[str] = []
        now = self.clock()
        cutoff = now - dt.timedelta(seconds=self.settings.release_ttl_seconds)
        with self.store.session() as s:
            holders: dict[str, list[tuple[Ticket, Action]]] = {}
            for ticket, action in s.execute(
                    select(Ticket, Action).join(Action, Action.ticket_id == Ticket.id)
                    .where(Action.active.is_(True), Action.kind == "ip_block",
                           Ticket.status.in_(("responding", "verified")))):
                holders.setdefault(action.target, []).append((ticket, action))
            for ip, pairs in holders.items():
                if all(t.updated_at <= cutoff for t, _ in pairs):
                    released += self._release_ip(s, ip, pairs)
        return released

    def _release_ip(self, s: Session, ip: str, pairs: list[tuple[Ticket, Action]]) -> list[str]:
        tickets = list({t.id: t for t, _ in pairs}.values())
        try:
            self.portal.unblock_ip(ip, f"{ip}-release-{int(self.clock().timestamp())}")
        except (PortalError, PortalUncertain) as exc:
            return self._release_failed(s, tickets, f"차단 해제 요청 실패: {exc}")
        if self._listed(ip) is not False:   # 여전히 차단 목록에 있거나 확인 불가
            return self._release_failed(s, tickets, "해제 뒤에도 차단 목록에 남아 있거나 확인할 수 없음")
        reachable = self.probe.is_reachable(ip)
        done = []
        for ticket in tickets:
            for _, action in (p for p in pairs if p[0].id == ticket.id):
                action.active = False
            action = self.store.add_action(
                s, ticket, kind="ip_release", target=ip, result="released", applied_verified=True,
                effect_verified=reachable, active=False, finished_at=self.clock(),
                effect_at=self.clock() if reachable is not None else None)
            self.store.advance(s, ticket, "restored")
            self.notifier.send(format_message("info", ticket, "released", [action],
                                              extra="승인: 자동 원복(TTL 경과)", now=self._aware()))
            done.append(ticket.id)
        return done

    def _release_failed(self, s: Session, tickets: list[Ticket], detail: str) -> list[str]:
        for ticket in tickets:
            ticket.release_attempts += 1
            s.commit()
            if ticket.release_attempts == 1:   # 매번 알리면 알림이 쌓이므로 첫 실패만
                self.notifier.send(format_message("error", ticket, "failed", extra=f"원복 실패: {detail}",
                                                  now=self._aware()))
        return []
