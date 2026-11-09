"""가입·로그인·로그아웃·내 정보."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from ..deps import SESSION_COOKIE, Ctx, csrf_guard, get_ctx, ok, set_session_cookie
from ..errors import ApiError
from ..models import LoginAttempt, LoginSession, User, utcnow
from ..security import DUMMY_HASH, hash_password, verify_password
from ..services import find_user, issue_session, public_user

router = APIRouter(prefix="/api/v1/auth", tags=["auth"], dependencies=[Depends(csrf_guard)])

USERNAME_PATTERN = r"^[A-Za-z0-9_]{3,40}$"


class RegisterBody(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(min_length=2, max_length=30)
    password: str = Field(min_length=10, max_length=128)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=128)


@router.get("/me")
def me(ctx: Ctx = Depends(get_ctx)):
    """현재 사용자와 CSRF 토큰. 세션이 없으면 비로그인 세션을 새로 만든다."""
    token = None
    session = ctx.session
    if session is None:
        token, session = issue_session(ctx.db, ctx.state.settings.session_ttl_seconds, None)
        ctx.db.commit()
    response = ok({"user": public_user(ctx.user), "csrf_token": session.csrf})
    if token:
        set_session_cookie(response, token, ctx.state)
    return response


@router.post("/register")
def register(body: RegisterBody, ctx: Ctx = Depends(get_ctx)):
    if ctx.user is not None:
        raise ApiError(409, "CONFLICT", "로그아웃 후 가입해 주세요.")
    username = body.username.lower()
    if find_user(ctx.db, username) is not None:
        raise ApiError(409, "CONFLICT", "이미 사용 중인 아이디입니다.")
    user = User(username=username, display_name=body.display_name, password_hash=hash_password(body.password),
                role="citizen")
    ctx.db.add(user)
    ctx.db.commit()
    return ok(public_user(user), 201)


@router.post("/login")
def login(body: LoginBody, ctx: Ctx = Depends(get_ctx)):
    settings = ctx.state.settings
    events = ctx.state.events
    username = body.username.lower()
    since = utcnow() - dt.timedelta(seconds=settings.login_rate_window_seconds)
    ctx.db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < since))
    recent = ctx.db.scalar(select(func.count()).select_from(LoginAttempt)
                           .where(LoginAttempt.src_ip == ctx.ip, LoginAttempt.created_at >= since)) or 0
    if recent >= settings.login_rate_limit:
        ctx.db.commit()
        events.emit("auth.login_failed", outcome="denied", status=429, src_ip=ctx.ip, username=username)
        raise ApiError(429, "RATE_LIMITED", "로그인 시도가 많습니다. 잠시 후 다시 시도해 주세요.")
    user = find_user(ctx.db, username)
    # 존재하지 않는 계정도 같은 계산 비용을 쓴다
    valid = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if user is None or not valid or user.locked:
        ctx.db.add(LoginAttempt(src_ip=ctx.ip))
        ctx.db.commit()
        events.emit("auth.login_failed", outcome="failure", status=401, src_ip=ctx.ip, username=username)
        raise ApiError(401, "INVALID_CREDENTIALS", "아이디·비밀번호 또는 계정 상태를 확인해 주세요.")
    # 로그인하면 세션을 새로 발급한다(세션 고정 공격 방지)
    if ctx.session is not None:
        ctx.db.execute(delete(LoginSession).where(LoginSession.id == ctx.session.id))
    token, session = issue_session(ctx.db, settings.session_ttl_seconds, user.id)
    ctx.db.commit()
    events.emit("auth.login_succeeded", outcome="success", status=200, src_ip=ctx.ip, username=user.username)
    response = ok({"user": public_user(user), "csrf_token": session.csrf})
    set_session_cookie(response, token, ctx.state)
    return response


@router.post("/logout")
def logout(ctx: Ctx = Depends(get_ctx)):
    if ctx.session is not None:
        ctx.db.execute(delete(LoginSession).where(LoginSession.id == ctx.session.id))
        ctx.db.commit()
    response = ok({"logged_out": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
