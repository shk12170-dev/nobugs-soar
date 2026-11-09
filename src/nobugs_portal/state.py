"""앱이 공유하는 객체(설정·DB·이벤트)."""
from __future__ import annotations

from dataclasses import dataclass

from .config import Settings
from .db import Database
from .events import EventSink


@dataclass
class AppState:
    settings: Settings
    db: Database
    events: EventSink

    @classmethod
    def build(cls, settings: Settings) -> AppState:
        db = Database(settings.database_url)
        db.create_all()
        return cls(settings=settings, db=db, events=EventSink(settings))
