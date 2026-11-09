"""요청마다 쓰는 의존성: DB 세션, 로그인 세션, CSRF, 권한."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from fastapi import Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .errors import ApiError
from .models import LoginSession, User, utcnow
from .netinfo import client_ip
from .security import safe_equal, token_hash
from .state import AppState

SESSION_COOKIE = "nb_session"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Ctx:
    db: Session
    state: AppState
    ip: str
    session: LoginSession | None
    user: User | None


def get_db(request: Request) -> Iterator[Session]:
    with request.app.state.nb.db.session() as db:
        yield db


def get_ctx(request: Request, db: Session = Depends(get_db)) -> Ctx:
    state: AppState = request.app.state.nb
    session = user = None
    raw = request.cookies.get(SESSION_COOKIE)
    if raw:
        row = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(raw)))
        if row is not None and row.expires_at > utcnow():
            session = row
            if row.user_id is not None:
                user = db.get(User, row.user_id)
    return Ctx(db=db, state=state, ip=client_ip(request), session=session, user=user)


def csrf_guard(request: Request, ctx: Ctx = Depends(get_ctx)) -> None:
    """변경 요청(POST 등)은 JSON 본문 + 같은 출처 + 세션의 CSRF 토큰이 모두 맞아야 한다."""
    if request.method not in UNSAFE_METHODS:
        return
    origin = request.headers.get("origin")
    if origin and origin != f"{request.url.scheme}://{request.headers.get('host', '')}":
        raise ApiError(403, "CSRF_FAILED", "다른 사이트에서 보낸 요청은 허용하지 않습니다.")
    supplied = request.headers.get("x-csrf-token", "")
    if ctx.session is None or not safe_equal(supplied, ctx.session.csrf):
        raise ApiError(403, "CSRF_FAILED", "보안 세션이 만료됐습니다. 새로고침 후 다시 시도해 주세요.")


def require_login(ctx: Ctx = Depends(get_ctx)) -> User:
    if ctx.user is None:
        raise ApiError(401, "UNAUTHENTICATED", "로그인이 필요합니다.")
    return ctx.user


def require_roles(*roles: str):
    def dependency(user: User = Depends(require_login)) -> User:
        if user.role not in roles:
            raise ApiError(403, "FORBIDDEN", "이 작업을 수행할 권한이 없습니다.")
        return user

    return dependency


is_citizen = require_roles("citizen")
is_staff = require_roles("staff", "admin")
is_admin = require_roles("admin")


def set_session_cookie(response: Response, token: str, state: AppState) -> None:
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", path="/",
                        secure=state.settings.cookie_secure, max_age=state.settings.session_ttl_seconds)


def ok(data, status: int = 200):
    from fastapi.responses import JSONResponse

    return JSONResponse({"data": data}, status_code=status)
