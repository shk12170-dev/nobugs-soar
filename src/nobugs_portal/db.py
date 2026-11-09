"""DB 연결. 포털(일반)과 대응 앱이 같은 파일을 쓰므로 SQLite는 WAL + 대기 시간을 설정한다."""
from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from .models import Base


class Database:
    def __init__(self, url: str) -> None:
        parsed = make_url(url)
        is_sqlite = parsed.get_backend_name() == "sqlite"
        if is_sqlite and parsed.database and parsed.database != ":memory:":
            Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, connect_args={"check_same_thread": False} if is_sqlite else {})
        if is_sqlite:
            @event.listens_for(self.engine, "connect")
            def _pragmas(dbapi_conn, _record):  # noqa: ANN001
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=5000")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()
        self._sessions = sessionmaker(self.engine, expire_on_commit=False)

    def create_all(self, attempts: int = 5) -> None:
        """표를 만든다. 일반 포털과 대응 앱이 동시에 시작하면 같은 표를 동시에 만들려다 실패할 수 있어 재시도한다."""
        for attempt in range(attempts):
            try:
                Base.metadata.create_all(self.engine)
                return
            except OperationalError as exc:
                if "already exists" not in str(exc) or attempt == attempts - 1:
                    raise
                time.sleep(0.1 * (attempt + 1))

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self._sessions()
        try:
            yield s
        finally:
            s.close()

    def dispose(self) -> None:
        self.engine.dispose()
