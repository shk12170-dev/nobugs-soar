"""대응 API(차단·해제·계정 잠금). 일반 포털과 **별도 앱**(별도 포트·프로세스)으로 띄운다.

서비스가 포화돼도 차단 요청이 일반 요청 뒤에 줄을 서지 않게 하려는 분리다.
호출 조건: ① 허용 대역의 출발지 ② 공용 키(X-Response-Key) ③ 변경 요청에는 멱등 키(Idempotency-Key).
키와 허용 대역이 설정되지 않으면 모든 요청을 거절한다.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
from collections.abc import Callable

from fastapi import APIRouter, Depends, FastAPI, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from .config import Settings
from .deps import Ctx, get_ctx, ok
from .errors import ApiError, install_error_handlers
from .models import BlockedIp, LoginSession, ResponseReceipt, User, utcnow
from .netinfo import client_ip, normalize_ip
from .security import safe_equal
from .services import find_user, revoke_sessions
from .state import AppState

IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{15,99}$")


def authenticate(request: Request) -> None:
    settings: Settings = request.app.state.nb.settings
    if not settings.response_api_key or not settings.response_allowed_cidrs:
        raise ApiError(403, "DISABLED", "대응 API가 설정되지 않았습니다.")
    ip = ipaddress.ip_address(client_ip(request)) if client_ip(request) != "unknown" else None
    if ip is None or not any(ip in ipaddress.ip_network(c, strict=False) for c in settings.response_allowed_cidrs):
        raise ApiError(403, "FORBIDDEN_NETWORK", "허용되지 않은 출발지입니다.")
    if not safe_equal(request.headers.get("x-response-key", ""), settings.response_api_key):
        raise ApiError(401, "UNAUTHORIZED", "키가 없거나 틀립니다.")


router = APIRouter(prefix="/api/v1/response", tags=["response"], dependencies=[Depends(authenticate)])


def idempotency_key(request: Request) -> str:
    key = request.headers.get("idempotency-key", "")
    if not IDEMPOTENCY_KEY.match(key):
        raise ApiError(400, "VALIDATION_ERROR", "Idempotency-Key(16~100자)가 필요합니다.")
    return key


def run_idempotent(ctx: Ctx, key: str, path: str, body: dict, action: Callable[[], dict]) -> tuple[dict, bool]:
    """같은 키·같은 본문이면 저장된 결과를 돌려주고(replayed=True), 다른 본문이면 409."""
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    fingerprint = hashlib.sha256(json.dumps([path, body], sort_keys=True).encode()).hexdigest()

    def replay() -> tuple[dict, bool] | None:
        receipt = ctx.db.get(ResponseReceipt, key_hash)
        if receipt is None:
            return None
        if receipt.fingerprint != fingerprint:
            raise ApiError(409, "IDEMPOTENCY_CONFLICT", "같은 키가 다른 내용으로 사용됐습니다.")
        return receipt.result, True

    found = replay()
    if found:
        return found
    result = action()
    ctx.db.add(ResponseReceipt(key_hash=key_hash, fingerprint=fingerprint, result=result))
    try:
        ctx.db.commit()
    except IntegrityError:  # 같은 키로 동시에 들어온 다른 요청이 먼저 끝났다
        ctx.db.rollback()
        found = replay()
        if found:
            return found
        raise
    return result, False


def parse_ip(raw: str) -> str:
    try:
        return normalize_ip(str(ipaddress.ip_address(raw.strip())))
    except ValueError as exc:
        raise ApiError(400, "VALIDATION_ERROR", "IP 주소 형식이 올바르지 않습니다.") from exc


class BlockBody(BaseModel):
    ip: str = Field(max_length=45)
    ttl_seconds: int | None = Field(default=None, ge=30, le=7 * 86400)


class UnblockBody(BaseModel):
    ip: str = Field(max_length=45)


class LockBody(BaseModel):
    username: str = Field(min_length=1, max_length=40)


@router.get("/ping")
def ping():
    return ok({"status": "ok"})


@router.get("/ips")
def list_blocked(ctx: Ctx = Depends(get_ctx)):
    now = utcnow()
    rows = ctx.db.scalars(select(BlockedIp).order_by(BlockedIp.created_at))
    items = [{"ip": r.ip, "created_at": r.created_at.isoformat(),
              "expires_at": r.expires_at.isoformat() if r.expires_at else None}
             for r in rows if r.expires_at is None or r.expires_at > now]
    return ok({"items": items})


@router.post("/ips/block")
def block_ip(body: BlockBody, request: Request, ctx: Ctx = Depends(get_ctx)):
    key = idempotency_key(request)
    ip = parse_ip(body.ip)

    def action() -> dict:
        expires = utcnow() + dt.timedelta(seconds=body.ttl_seconds) if body.ttl_seconds else None
        row = ctx.db.get(BlockedIp, ip)
        changed = row is None or (row.expires_at is not None and row.expires_at <= utcnow())
        if row is None:
            ctx.db.add(BlockedIp(ip=ip, expires_at=expires))
        else:
            row.expires_at, row.created_at = expires, utcnow() if changed else row.created_at
        return {"ip": ip, "blocked": True, "changed": changed, "expires_at": expires.isoformat() if expires else None}

    result, replayed = run_idempotent(ctx, key, "/ips/block", {"ip": ip, "ttl": body.ttl_seconds}, action)
    if not replayed:
        ctx.state.events.emit("response.ip_blocked", outcome="success", status=200, src_ip=ctx.ip, target_ip=ip)
    return ok({**result, "replayed": replayed})


@router.post("/ips/unblock")
def unblock_ip(body: UnblockBody, request: Request, ctx: Ctx = Depends(get_ctx)):
    key = idempotency_key(request)
    ip = parse_ip(body.ip)

    def action() -> dict:
        row = ctx.db.get(BlockedIp, ip)
        if row is not None:
            ctx.db.delete(row)
        return {"ip": ip, "blocked": False, "changed": row is not None}

    result, replayed = run_idempotent(ctx, key, "/ips/unblock", {"ip": ip}, action)
    if not replayed:
        ctx.state.events.emit("response.ip_unblocked", outcome="success", status=200, src_ip=ctx.ip, target_ip=ip)
    return ok({**result, "replayed": replayed})


@router.post("/accounts/lock")
def lock_account(body: LockBody, request: Request, ctx: Ctx = Depends(get_ctx)):
    """계정을 잠그고 모든 세션을 지운다. 관리자 계정은 자동 대응 대상이 아니다."""
    key = idempotency_key(request)
    username = body.username.lower()
    target: User | None = find_user(ctx.db, username)
    if target is None:
        raise ApiError(404, "NOT_FOUND", "계정을 찾을 수 없습니다.")
    if target.role == "admin":
        raise ApiError(403, "FORBIDDEN", "관리자 계정은 자동 대응 대상에서 제외합니다.")

    def action() -> dict:
        changed = not target.locked
        target.locked = True
        revoked = revoke_sessions(ctx.db, target.id)
        return {"user_id": target.id, "locked": True, "changed": changed, "revoked_sessions": revoked}

    result, replayed = run_idempotent(ctx, key, "/accounts/lock", {"username": username}, action)
    if not replayed:
        ctx.state.events.emit("auth.account_locked", outcome="success", status=200, src_ip=ctx.ip,
                              username=username, by="response-api")
    return ok({**result, "replayed": replayed})


@router.get("/accounts/{username}")
def account_state(username: str, ctx: Ctx = Depends(get_ctx)):
    """계정 잠금과 살아 있는 세션 수. 잠금이 실제로 적용됐는지 확인하는 용도(읽기 전용)."""
    target = find_user(ctx.db, username[:40])
    if target is None:
        raise ApiError(404, "NOT_FOUND", "계정을 찾을 수 없습니다.")
    sessions = ctx.db.scalar(select(func.count()).select_from(LoginSession)
                             .where(LoginSession.user_id == target.id, LoginSession.expires_at > utcnow())) or 0
    return ok({"username": target.username, "locked": target.locked, "active_sessions": sessions, "role": target.role})


def create_control_app(settings: Settings | None = None, state: AppState | None = None) -> FastAPI:
    state = state or AppState.build(settings or Settings.from_env())
    app = FastAPI(title="nobugs response api", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.nb = state
    install_error_handlers(app)
    app.include_router(router)
    return app


def control_factory() -> FastAPI:
    """uvicorn nobugs_portal.control:control_factory --factory"""
    return create_control_app(Settings.from_env())
