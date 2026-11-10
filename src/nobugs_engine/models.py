"""엔진 DB 모델. 시각은 UTC(시간대 정보 없음)로 저장한다."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

STATUSES = ("open", "responding", "verified", "restored", "closed")


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Ticket(Base):
    """사건 한 건. (케이스, 묶음 키)마다 닫히지 않은 티켓은 하나뿐이다."""

    __tablename__ = "tickets"
    __table_args__ = (
        Index("uq_open_ticket", "case_id", "group_key", unique=True, sqlite_where=text("status != 'closed'")),
    )

    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(10))
    group_key: Mapped[str] = mapped_column(String(120))
    status: Mapped[str] = mapped_column(String(12), default="open")  # open|responding|verified|restored|closed
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    username: Mapped[str | None] = mapped_column(String(40), nullable=True)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    condition_met_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    detected_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    close_note: Mapped[str] = mapped_column(Text, default="")
    release_attempts: Mapped[int] = mapped_column(Integer, default=0)


class Action(Base):
    """티켓에 속한 조치 한 줄. active는 지금도 효력이 있는 차단인지(원복되면 False)."""

    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))        # ip_block | ip_release
    target: Mapped[str] = mapped_column(String(80))
    result: Mapped[str] = mapped_column(String(20))      # dry_run|applied|already_applied|failed|uncertain|released
    applied_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    effect_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[str] = mapped_column(String(300), default="")
    requested_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    effect_at: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    content: Mapped[str] = mapped_column(Text)
