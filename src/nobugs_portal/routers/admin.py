"""관리자: 계정 조회·잠금·해제·비밀번호 재설정."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from ..deps import Ctx, csrf_guard, get_ctx, is_admin, ok
from ..errors import ApiError
from ..models import User
from ..security import hash_password
from ..services import public_user, revoke_sessions

router = APIRouter(prefix="/api/v1/admin/users", tags=["admin"], dependencies=[Depends(csrf_guard)])


class ResetBody(BaseModel):
    new_password: str = Field(min_length=10, max_length=128)


def _target(ctx: Ctx, user_id: int) -> User:
    target = ctx.db.get(User, user_id)
    if target is None:
        raise ApiError(404, "NOT_FOUND", "계정을 찾을 수 없습니다.")
    return target


@router.get("")
def list_users(q: str | None = Query(default=None, max_length=40), role: str | None = None,
               locked: bool | None = None, limit: int = Query(default=50, ge=1, le=200),
               ctx: Ctx = Depends(get_ctx), _: User = Depends(is_admin)):
    query = select(User)
    if q:
        like = f"%{q.lower()}%"
        query = query.where(or_(func.lower(User.username).like(like), func.lower(User.display_name).like(like)))
    if role:
        query = query.where(User.role == role)
    if locked is not None:
        query = query.where(User.locked == locked)
    rows = list(ctx.db.scalars(query.order_by(User.id).limit(limit)))
    total = ctx.db.scalar(select(func.count()).select_from(query.subquery())) or 0
    return ok({"total": total, "items": [{**public_user(u), "locked": u.locked} for u in rows]})


@router.post("/{user_id}/lock")
def lock(user_id: int, ctx: Ctx = Depends(get_ctx), admin: User = Depends(is_admin)):
    target = _target(ctx, user_id)
    if target.id == admin.id:
        raise ApiError(409, "CONFLICT", "자기 자신의 계정은 잠글 수 없습니다.")
    changed = not target.locked
    target.locked = True
    revoked = revoke_sessions(ctx.db, target.id)
    ctx.db.commit()
    ctx.state.events.emit("auth.account_locked", outcome="success", status=200, src_ip=ctx.ip, username=target.username)
    return ok({"user_id": target.id, "locked": True, "changed": changed, "revoked_sessions": revoked})


@router.post("/{user_id}/unlock")
def unlock(user_id: int, ctx: Ctx = Depends(get_ctx), _: User = Depends(is_admin)):
    target = _target(ctx, user_id)
    changed = target.locked
    target.locked = False
    ctx.db.commit()
    return ok({"user_id": target.id, "locked": False, "changed": changed})


@router.post("/{user_id}/reset-password")
def reset_password(user_id: int, body: ResetBody, ctx: Ctx = Depends(get_ctx),
                   _: User = Depends(is_admin)):
    """비밀번호를 바꾸고 잠금을 풀며 기존 세션을 모두 지운다(탈취 의심 계정의 사람 복구 절차)."""
    target = _target(ctx, user_id)
    target.password_hash = hash_password(body.new_password)
    target.locked = False
    revoked = revoke_sessions(ctx.db, target.id)
    ctx.db.commit()
    ctx.state.events.emit("auth.password_reset", outcome="success", status=200, src_ip=ctx.ip, username=target.username)
    return ok({"user_id": target.id, "locked": False, "revoked_sessions": revoked})
