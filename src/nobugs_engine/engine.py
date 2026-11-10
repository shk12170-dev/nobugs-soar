"""대응 엔진 핵심 로직(S1·S4·S8·S10·S12). 규칙은 docs/BEHAVIOR-SPEC.md 4절의 안전 규칙을 따른다.

1 기본은 모의 실행  2 보호 대상은 차단하지 않음  3 변경 호출은 멱등 키, 불확실한 결과는 재조회로 대조
4 (케이스, 키)당 열린 티켓 1개, 같은 IP를 쓰는 티켓이 여럿이어도 원복이 교착되지 않음
5 자동 원복은 TTL 경과 후에만, 효과를 확인하고 티켓에 남김. 계정 잠금(S4)은 자동 해제하지 않고 사람이 복구
6 S12는 서비스가 실제로 느려졌을 때만 차단. S10은 경계 → 앱 순서로 원복
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass

from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import EngineSettings
from .health import HealthChecker, decide
from .models import Action, Ticket, utcnow
from .notify import Notifier, format_message
from .portal import BoundaryControl, PortalControl, PortalError, PortalUncertain
from .probe import EffectProbe
from .store import InvalidTransition, Store


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

    @field_validator("username")
    @classmethod
    def _blank_username(cls, value: str | None) -> str | None:
        # Graylog 정의는 계정이 없는 케이스에 "-"를 채워 보낸다
        return None if value is None or value.strip() in ("", "-") else value


SCAN_CASES = ("S8", "S10")
IP_KINDS = ("ip_block", "boundary_block")


@dataclass(frozen=True)
class CaseSpec:
    title: str
    kind: str            # ip_user | account | scan | flood

    def group_key(self, d: Detection, ip: str) -> str:
        if self.kind in ("scan", "flood"):
            return ip
        return f"{d.username or '-'}@{ip}"


CASES: dict[str, CaseSpec] = {
    "S1": CaseSpec("로그인 반복 실패(무차별 대입)", "ip_user"),
    "S4": CaseSpec("로그인 실패 뒤 성공(계정 탈취 의심)", "account"),
    "S8": CaseSpec("웹 스캔 뒤 로그인 시도", "scan"),
    "S10": CaseSpec("스캔·로그인·경계 차단 신호 연쇄", "scan"),
    "S12": CaseSpec("요청 폭주", "flood"),
}


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
                 notifier: Notifier, clock: Callable[[], dt.datetime] = utcnow,
                 boundary: BoundaryControl | None = None, health: HealthChecker | None = None) -> None:
        self.settings, self.store, self.portal, self.probe, self.notifier, self.clock = (
            settings, store, portal, probe, notifier, clock)
        self.boundary, self.health = boundary, health
        store.clock = clock
        self._protected = [ipaddress.ip_network(c, strict=False) for c in settings.protected_cidrs]
        # 웹훅은 스레드풀에서 동시에 들어올 수 있다(예: S8·S10 정의가 같은 트래픽에 같은 분 안에 함께 발동).
        # 같은 묶음 키에 두 번 조치하지 않도록 엔진의 판단·조치 구간 전체를 하나씩 처리한다.
        self._lock = threading.Lock()

    # ---- 탐지 처리 ----
    def is_protected(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self._protected)

    def handle(self, d: Detection) -> dict:
        with self._lock:
            return self._handle_locked(d)

    def _handle_locked(self, d: Detection) -> dict:
        spec = CASES.get(d.case_id)
        if spec is None:
            return {"verdict": "unsupported_case", "case_id": d.case_id}
        try:
            ip = str(ipaddress.ip_address(d.src_ip))
        except ValueError:
            return {"verdict": "invalid_input", "detail": "src_ip"}
        if spec.kind == "account" and not d.username:
            return {"verdict": "invalid_input", "detail": "username"}
        if self.is_protected(ip):
            return {"verdict": "protected_source", "src_ip": ip, "no_action": True}
        dry_run = self.settings.default_dry_run if d.dry_run is None else d.dry_run
        prefix = self.settings.live_account_prefix
        if spec.kind == "account" and not dry_run and not (d.username or "").startswith(prefix):
            return {"verdict": "protected_account", "no_action": True,
                    "detail": f"실제 잠금은 '{prefix}' 시험 계정에만 허용"}
        extra = ""
        if spec.kind == "flood":
            verdict, kinds, ms = self._health_verdict()
            if verdict != "exceeded":
                return {"verdict": verdict, "no_action": True, "samples": kinds, "ms": ms}
            extra = f"서비스 지연 확인: 기준 {self.settings.health_baseline_ms:.0f}ms 초과 {len(kinds)}회 연속"
        with self.store.session() as s:
            ticket = self._ticket_for(s, d, spec, ip)
            if d.event_id not in ticket.event_ids:
                ticket.event_ids = [*ticket.event_ids, d.event_id]
                s.commit()
            missing = [k for k in self._kinds_needed(d.case_id) if not self._has(s, ticket, k, dry_run)]
            if not missing:
                return {"verdict": "duplicate", "ticket_id": ticket.id, "status": ticket.status}
            if dry_run:
                actions = [self.store.add_action(s, ticket, kind=k, target=self._target(k, ip, d), result="dry_run",
                                                 detail="모의 실행: 아무것도 호출하지 않았다", finished_at=self.clock())
                           for k in missing]
                self.notifier.send(format_message("warn", ticket, "dry_run", actions, extra=extra,
                                                  now=self._aware()))
                return {"verdict": "dry_run", "ticket_id": ticket.id, "status": ticket.status}
            return self._apply(s, ticket, ip, d, missing, extra)

    def _health_verdict(self) -> tuple[str, list[str], list[float | None]]:
        samples = self.health.run() if self.health else []
        verdict, kinds = decide(samples, self.settings.health_baseline_ms)
        return verdict, kinds, [None if x.ms is None else round(x.ms, 1) for x in samples]

    # ---- 티켓 ----
    def _ticket_for(self, s: Session, d: Detection, spec: CaseSpec, ip: str) -> Ticket:
        cases = SCAN_CASES if spec.kind == "scan" else (d.case_id,)
        key = spec.group_key(d, ip)
        restored = s.scalar(select(Ticket).where(Ticket.case_id.in_(cases), Ticket.group_key == key,
                                                 Ticket.status == "restored"))
        if restored is not None:
            # 원복된 티켓은 효력이 남은 조치가 없으므로 닫아도 살아 있는 조치를 가리지 않는다 → 새 라운드
            self.store.close(s, restored.id, "자동 종료: 원복 뒤 같은 대상에서 새 탐지가 발생해 새 사건으로 처리")
        if spec.kind == "scan":
            existing = self.store.find_open(s, SCAN_CASES, key)
            if existing is not None:
                if d.case_id == "S10" and existing.case_id == "S8":
                    self.store.upgrade_case(s, existing, "S10")     # 스캔이 경계 신호까지 번졌다
                return existing
        ticket, _ = self.store.open_or_get(
            s, d.case_id, key, src_ip=ip, username=d.username,
            condition_met_at=parse_time(d.condition_met_at), detected_at=parse_time(d.detected_at))
        return ticket

    @staticmethod
    def _kinds_needed(case_id: str) -> list[str]:
        return {"S4": ["account_lock"], "S10": ["boundary_block", "ip_block"]}.get(case_id, ["ip_block"])

    @staticmethod
    def _target(kind: str, ip: str, d: Detection) -> str:
        return (d.username or "-") if kind == "account_lock" else ip

    def _has(self, s: Session, ticket: Ticket, kind: str, dry_run: bool) -> bool:
        actions = [a for a in self.store.actions_of(s, ticket.id) if a.kind == kind]
        if dry_run:
            return bool(actions)
        return any(a.active or a.result in ("applied", "already_applied") for a in actions)

    def _aware(self) -> dt.datetime:
        return self.clock().replace(tzinfo=dt.UTC)

    # ---- 실제 조치 ----
    def _apply(self, s: Session, ticket: Ticket, ip: str, d: Detection, missing: list[str], extra: str) -> dict:
        actions = []
        for kind in missing:        # S10은 경계를 먼저, 그다음 앱
            if kind == "boundary_block":
                actions.append(self._attempt_boundary_block(s, ticket, ip))
            elif kind == "ip_block":
                actions.append(self._attempt_ip_block(s, ticket, ip))
            else:
                actions.append(self._attempt_account_lock(s, ticket, d.username or ""))
        primary = [a for a in actions if a.kind in ("ip_block", "account_lock")]
        any_active = any(a.active for a in actions)
        effective = bool(primary) and all(a.active and a.effect_verified is True for a in primary)
        if effective:
            self.store.advance(s, ticket, "verified")
        elif any_active and ticket.status == "open":      # 이미 verified인 티켓의 상태를 되돌리지 않는다
            self.store.advance(s, ticket, "responding")
        main = next((a for a in primary if a.active), primary[0] if primary else actions[0])
        failed = [a for a in actions if not a.active]
        self.notifier.send(format_message("error" if failed else "warn", ticket, main.result, actions, extra=extra,
                                          now=self._aware()))
        return {"verdict": "responded" if any_active else "failed", "ticket_id": ticket.id,
                "status": ticket.status, "result": main.result, "actions": [f"{a.kind}:{a.result}" for a in actions],
                "applied_verified": main.applied_verified, "effect_verified": main.effect_verified}

    def _record(self, s: Session, ticket: Ticket, kind: str, target: str, result: str, requested: dt.datetime,
                **fields) -> Action:
        return self.store.add_action(s, ticket, kind=kind, target=target, result=result, requested_at=requested,
                                     finished_at=self.clock(), **fields)

    def _attempt_ip_block(self, s: Session, ticket: Ticket, ip: str) -> Action:
        requested, detail = self.clock(), ""
        try:
            changed = self.portal.block_ip(ip, f"{ticket.id}-block-{ip}").get("changed")
            result = "applied" if changed else "already_applied"
        except PortalError as exc:
            return self._record(s, ticket, "ip_block", ip, "failed", requested, applied_verified=False,
                                active=False, detail=f"포털이 거절함: {exc}"[:300])
        except PortalUncertain as exc:
            # 불확실한 결과: 실제 차단 목록을 다시 보고 사실대로 기록한다(자동 재시도 없음)
            if not self._listed(ip):
                return self._record(s, ticket, "ip_block", ip, "uncertain", requested, applied_verified=False,
                                    active=False, detail=f"{exc} → 재조회에서도 확인 불가"[:300])
            result, detail = "applied", f"{exc} → 재조회로 적용 확인"
        listed = self._listed(ip)
        effect = self.probe.is_blocked(ip)
        return self._record(s, ticket, "ip_block", ip, result, requested, applied_verified=listed,
                            effect_verified=effect, active=True, detail=detail,
                            effect_at=self.clock() if effect is not None else None)

    def _attempt_boundary_block(self, s: Session, ticket: Ticket, ip: str) -> Action:
        requested = self.clock()
        if self.boundary is None:
            return self._record(s, ticket, "boundary_block", ip, "failed", requested, applied_verified=False,
                                active=False, detail="경계 제어가 설정되지 않음")
        try:
            result = "applied" if self.boundary.block_ip(ip).get("changed") else "already_applied"
            listed = ip in self.boundary.blocked_ips()
        except PortalError as exc:
            return self._record(s, ticket, "boundary_block", ip, "failed", requested, applied_verified=False,
                                active=False, detail=f"경계가 거절함: {exc}")
        except PortalUncertain as exc:
            return self._record(s, ticket, "boundary_block", ip, "uncertain", requested, applied_verified=False,
                                active=False, detail=f"{exc} (자동 재시도 없음)")
        # 경계는 시뮬레이터라 실제 패킷 차단 효과는 확인하지 않는다(효과 확인 = 없음)
        return self._record(s, ticket, "boundary_block", ip, result, requested, applied_verified=listed,
                            active=True, detail="시뮬레이션: 목록만 관리, 실제 패킷 차단 아님")

    def _attempt_account_lock(self, s: Session, ticket: Ticket, username: str) -> Action:
        requested, detail = self.clock(), ""
        try:
            changed = self.portal.lock_account(username, f"{ticket.id}-lock-{username}").get("changed")
            result = "applied" if changed else "already_applied"
        except PortalError as exc:
            return self._record(s, ticket, "account_lock", username, "failed", requested, applied_verified=False,
                                active=False, detail=f"포털이 거절함: {exc}"[:300])
        except PortalUncertain as exc:
            state = self._account_state(username)
            if not (state and state.get("locked")):
                return self._record(s, ticket, "account_lock", username, "uncertain", requested,
                                    applied_verified=False, active=False, detail=f"{exc} → 재조회에서도 확인 불가")
            result, detail = "applied", f"{exc} → 재조회로 적용 확인"
        state = self._account_state(username)
        locked = None if state is None else bool(state.get("locked"))
        effect = None if state is None else bool(state.get("locked")) and state.get("active_sessions", 1) == 0
        return self._record(s, ticket, "account_lock", username, result, requested, applied_verified=locked,
                            effect_verified=effect, active=True, detail=detail,
                            effect_at=self.clock() if effect is not None else None)

    def _listed(self, ip: str) -> bool | None:
        try:
            return ip in self.portal.blocked_ips()
        except (PortalError, PortalUncertain):
            return None

    def _account_state(self, username: str) -> dict | None:
        try:
            return self.portal.account_state(username)
        except (PortalError, PortalUncertain):
            return None

    # ---- 사람이 하는 계정 복구 확인(S4) ----
    def confirm_account_recovered(self, ticket_id: str) -> dict:
        """관리자가 포털에서 잠금을 푼 뒤 호출한다. 실제로 풀렸는지 포털에서 확인하고 티켓을 원복 처리한다."""
        with self._lock, self.store.session() as s:
            ticket = self.store.get(s, ticket_id)
            locks = [a for a in self.store.actions_of(s, ticket_id) if a.kind == "account_lock" and a.active]
            if not locks:
                raise InvalidTransition("효력이 남은 계정 잠금이 없습니다.")
            username = locks[0].target
            state = self._account_state(username)
            if state is None:
                raise InvalidTransition("포털에서 계정 상태를 확인할 수 없습니다.")
            if state.get("locked"):
                raise InvalidTransition("계정이 아직 잠겨 있습니다. 관리자가 잠금을 푼 뒤 다시 확인하세요.")
            for a in locks:
                a.active = False
            action = self.store.add_action(s, ticket, kind="account_unlock", target=username, result="released",
                                           applied_verified=True, effect_verified=True, active=False,
                                           finished_at=self.clock(), effect_at=self.clock(),
                                           detail="사람이 잠금을 해제, 엔진이 포털에서 확인")
            self.store.advance(s, ticket, "restored")
            self.notifier.send(format_message("info", ticket, "released", [action],
                                              extra="승인: 관리자 수동 복구", now=self._aware()))
            return {"ticket_id": ticket.id, "status": ticket.status}

    # ---- 자동 원복 ----
    def release_due(self) -> list[str]:
        """TTL이 지난 IP 차단을 푼다. 같은 IP를 쓰는 티켓은 모두 TTL이 지났을 때 한꺼번에 푼다(교착 없음)."""
        released: list[str] = []
        cutoff = self.clock() - dt.timedelta(seconds=self.settings.release_ttl_seconds)
        with self._lock, self.store.session() as s:
            holders: dict[str, list[tuple[Ticket, Action]]] = {}
            for ticket, action in s.execute(
                    select(Ticket, Action).join(Action, Action.ticket_id == Ticket.id)
                    .where(Action.active.is_(True), Action.kind.in_(IP_KINDS),
                           Ticket.status.in_(("responding", "verified")))):
                holders.setdefault(action.target, []).append((ticket, action))
            for ip, pairs in holders.items():
                if all(t.updated_at <= cutoff for t, _ in pairs):
                    released += self._release_ip(s, ip, pairs)
        return released

    def _release_boundary(self, ip: str) -> str | None:
        """경계 차단을 풀고 목록에서 사라졌는지 확인한다. 실패 사유를 돌려주고, 성공이면 None."""
        if self.boundary is None:
            return "경계 제어가 설정되지 않음"
        try:
            self.boundary.unblock_ip(ip)
            still = ip in self.boundary.blocked_ips()
        except (PortalError, PortalUncertain) as exc:
            return f"경계 해제 실패: {exc}"
        return "경계 해제 뒤에도 차단 목록에 남아 있음" if still else None

    def _release_ip(self, s: Session, ip: str, pairs: list[tuple[Ticket, Action]]) -> list[str]:
        tickets = list({t.id: t for t, _ in pairs}.values())
        # 순서: 경계 → 앱. 경계 해제를 확인하지 못하면 앱도 풀지 않는다.
        if any(a.kind == "boundary_block" for _, a in pairs):
            problem = self._release_boundary(ip)
            if problem:
                return self._release_failed(s, tickets, problem)
        reachable = None
        if any(a.kind == "ip_block" for _, a in pairs):
            try:
                self.portal.unblock_ip(ip, f"{ip}-release-{int(self.clock().timestamp())}")
            except (PortalError, PortalUncertain) as exc:
                return self._release_failed(s, tickets, f"차단 해제 요청 실패: {exc}")
            if self._listed(ip) is not False:   # 여전히 차단 목록에 있거나 확인 불가
                return self._release_failed(s, tickets, "해제 뒤에도 차단 목록에 남아 있거나 확인할 수 없음")
            reachable = self.probe.is_reachable(ip)
        done = []
        for ticket in tickets:
            mine = [a for t, a in pairs if t.id == ticket.id]
            recorded = []
            for a in mine:
                a.active = False
                app = a.kind == "ip_block"
                recorded.append(self.store.add_action(
                    s, ticket, kind="ip_release" if app else "boundary_release", target=ip, result="released",
                    applied_verified=True, effect_verified=reachable if app else None, active=False,
                    finished_at=self.clock(), effect_at=self.clock() if app and reachable is not None else None))
            self.store.advance(s, ticket, "restored")
            self.notifier.send(format_message("info", ticket, "released", recorded,
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
