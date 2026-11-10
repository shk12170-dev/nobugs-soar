"""티켓 저장소: 상태 기계와 조회. 상태는 open → responding → verified → restored → closed 순으로만 간다.

닫기는 사람이 한다. 효력이 남은 조치(active)가 있으면 닫을 수 없다(닫힌 티켓이 살아 있는 차단을 가리면 안 된다).
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .models import Action, Base, Notification, Ticket, utcnow

CLOSABLE = ("restored",)
ORDER = {"open": 0, "responding": 1, "verified": 2, "restored": 3, "closed": 4}


class StoreError(Exception):
    pass


class InvalidTransition(StoreError):
    pass


class NotFound(StoreError):
    pass


class Store:
    def __init__(self, url: str, clock: Callable[[], dt.datetime] = utcnow) -> None:
        self.clock = clock   # 시각은 모두 이 시계로 찍는다(엔진이 같은 시계를 쓰도록 주입할 수 있다)
        parsed = make_url(url)
        sqlite = parsed.get_backend_name() == "sqlite"
        if sqlite and parsed.database and parsed.database != ":memory:":
            Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, connect_args={"check_same_thread": False} if sqlite else {})
        if sqlite:
            @event.listens_for(self.engine, "connect")
            def _pragmas(conn, _record):  # noqa: ANN001
                cur = conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=5000")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()
        Base.metadata.create_all(self.engine)
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._sessions()
        try:
            yield s
        finally:
            s.close()

    def dispose(self) -> None:
        self.engine.dispose()

    # ---- 티켓 ----
    def _next_id(self, s: Session, now: dt.datetime) -> str:
        prefix = f"T-{now:%Y%m%d}-"
        count = s.scalar(select(func.count()).select_from(Ticket).where(Ticket.id.like(prefix + "%"))) or 0
        return f"{prefix}{count + 1:04d}"

    def open_or_get(self, s: Session, case_id: str, group_key: str, **fields) -> tuple[Ticket, bool]:
        """닫히지 않은 티켓이 있으면 그것을, 없으면 새로 만든다. (티켓, 새로 만들었는지)"""
        existing = s.scalar(select(Ticket).where(Ticket.case_id == case_id, Ticket.group_key == group_key,
                                                 Ticket.status != "closed"))
        if existing is not None:
            return existing, False
        now = self.clock()
        for _ in range(5):  # 같은 순간 다른 요청이 같은 번호/키로 만들면 다시 시도
            ticket = Ticket(id=self._next_id(s, now), case_id=case_id, group_key=group_key, created_at=now,
                            updated_at=now, **fields)
            s.add(ticket)
            try:
                s.commit()
                return ticket, True
            except IntegrityError:
                s.rollback()
                existing = s.scalar(select(Ticket).where(Ticket.case_id == case_id, Ticket.group_key == group_key,
                                                         Ticket.status != "closed"))
                if existing is not None:
                    return existing, False
        raise StoreError("티켓 번호를 할당하지 못했습니다.")

    def find_open(self, s: Session, cases: tuple[str, ...], group_key: str) -> Ticket | None:
        return s.scalar(select(Ticket).where(Ticket.case_id.in_(cases), Ticket.group_key == group_key,
                                             Ticket.status != "closed"))

    def upgrade_case(self, s: Session, ticket: Ticket, case_id: str) -> None:
        """같은 대상에서 더 넓은 사건(S8 -> S10)으로 번졌을 때 같은 티켓을 승격한다."""
        ticket.case_id = case_id
        ticket.updated_at = self.clock()
        s.commit()

    def get(self, s: Session, ticket_id: str) -> Ticket:
        ticket = s.get(Ticket, ticket_id)
        if ticket is None:
            raise NotFound(ticket_id)
        return ticket

    def advance(self, s: Session, ticket: Ticket, status: str) -> None:
        """앞으로만 간다. 같은 상태로의 반복 호출은 무시하고, 되돌리기는 거절한다."""
        if status not in ORDER:
            raise InvalidTransition(f"알 수 없는 상태: {status}")
        if ORDER[status] < ORDER[ticket.status]:
            raise InvalidTransition(f"{ticket.status}에서 {status}로 되돌릴 수 없습니다.")
        if ticket.status != status:
            ticket.status = status
        ticket.updated_at = self.clock()
        s.commit()

    def add_action(self, s: Session, ticket: Ticket, **fields) -> Action:
        action = Action(ticket_id=ticket.id, **fields)
        s.add(action)
        ticket.updated_at = self.clock()
        s.commit()
        return action

    def active_actions(self, s: Session, ticket_id: str) -> list[Action]:
        return list(s.scalars(select(Action).where(Action.ticket_id == ticket_id, Action.active.is_(True))))

    def close(self, s: Session, ticket_id: str, note: str) -> Ticket:
        ticket = self.get(s, ticket_id)
        if ticket.status not in CLOSABLE:
            raise InvalidTransition(f"{ticket.status} 상태의 티켓은 닫을 수 없습니다(원복 완료 뒤에만 가능).")
        if self.active_actions(s, ticket_id):
            raise InvalidTransition("효력이 남은 조치가 있어 닫을 수 없습니다.")
        ticket.status, ticket.closed_at, ticket.close_note = "closed", self.clock(), note[:200]
        ticket.updated_at = self.clock()
        s.commit()
        return ticket

    def list(self, s: Session, status: str | None = None, limit: int = 100) -> list[Ticket]:
        query = select(Ticket).order_by(Ticket.created_at.desc(), Ticket.id.desc()).limit(limit)
        if status:
            query = query.where(Ticket.status == status)
        return list(s.scalars(query))

    def actions_of(self, s: Session, ticket_id: str) -> list[Action]:
        return list(s.scalars(select(Action).where(Action.ticket_id == ticket_id).order_by(Action.id)))

    # ---- 알림 ----
    def add_notification(self, content: str) -> None:
        with self.session() as s:
            s.add(Notification(content=content))
            s.commit()

    def notifications(self, limit: int = 50) -> list[Notification]:
        with self.session() as s:
            return list(s.scalars(select(Notification).order_by(Notification.id.desc()).limit(limit)))
