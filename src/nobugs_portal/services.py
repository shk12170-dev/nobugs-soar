"""여러 라우터가 함께 쓰는 DB 작업."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import BlockedIp, LoginSession, User, utcnow
from .security import new_token, token_hash


def is_blocked(db: Session, ip: str) -> bool:
    row = db.get(BlockedIp, ip)
    return row is not None and (row.expires_at is None or row.expires_at > utcnow())


def revoke_sessions(db: Session, user_id: int) -> int:
    """계정의 모든 세션을 지운다. 지운 개수를 돌려준다(커밋은 호출한 쪽에서)."""
    result = db.execute(delete(LoginSession).where(LoginSession.user_id == user_id))
    return result.rowcount or 0


def issue_session(db: Session, ttl_seconds: int, user_id: int | None) -> tuple[str, LoginSession]:
    token = new_token()
    row = LoginSession(token_hash=token_hash(token), user_id=user_id, csrf=new_token(),
                       expires_at=utcnow() + dt.timedelta(seconds=ttl_seconds))
    db.add(row)
    db.flush()
    return token, row


def find_user(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username.lower()))


def public_user(user: User | None) -> dict | None:
    if user is None:
        return None
    return {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role}
