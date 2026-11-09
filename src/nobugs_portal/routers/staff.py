"""담당자·관리자의 민원 처리: 목록·배정·상태 변경·답변."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..deps import Ctx, csrf_guard, get_ctx, is_staff, ok
from ..errors import ApiError
from ..models import Petition, PetitionHistory, User, utcnow
from .petitions import history_of, petition_out

router = APIRouter(prefix="/api/v1/staff/petitions", tags=["staff"], dependencies=[Depends(csrf_guard)])

STATUSES = ("received", "assigned", "processing", "done")
# 허용하는 상태 전이: 처리 순서를 건너뛰거나 되돌릴 수 없다
TRANSITIONS = {"assigned": "processing", "processing": "done"}


class AssignBody(BaseModel):
    assignee_id: int | None = None


class StatusBody(BaseModel):
    status: str = Field(pattern="^(processing|done)$")
    expected_version: int = Field(ge=1)
    note: str = Field(default="", max_length=500)


class ReplyBody(BaseModel):
    note: str = Field(min_length=1, max_length=1000)


def _load(ctx: Ctx, petition_id: int) -> Petition:
    petition = ctx.db.get(Petition, petition_id)
    if petition is None:
        raise ApiError(404, "NOT_FOUND", "민원을 찾을 수 없습니다.")
    return petition


def _touch(petition: Petition) -> None:
    petition.version += 1
    petition.updated_at = utcnow()


@router.get("")
def list_all(status: str | None = Query(default=None), ctx: Ctx = Depends(get_ctx),
             _: User = Depends(is_staff)):
    if status is not None and status not in STATUSES:
        raise ApiError(400, "VALIDATION_ERROR", "status 값을 확인해 주세요.")
    query = select(Petition).order_by(Petition.id.desc())
    if status:
        query = query.where(Petition.status == status)
    return ok({"items": [petition_out(p) for p in ctx.db.scalars(query)]})


@router.post("/{petition_id}/assign")
def assign(petition_id: int, body: AssignBody, ctx: Ctx = Depends(get_ctx),
           user: User = Depends(is_staff)):
    petition = _load(ctx, petition_id)
    if petition.status not in ("received", "assigned"):
        raise ApiError(409, "CONFLICT", "이미 처리가 시작된 민원은 배정을 바꿀 수 없습니다.")
    target_id = body.assignee_id if body.assignee_id is not None else user.id
    # 담당자는 자기 자신만, 관리자는 담당자 누구에게나 배정할 수 있다
    if user.role == "staff" and target_id != user.id:
        raise ApiError(403, "FORBIDDEN", "담당자는 자기 자신에게만 배정할 수 있습니다.")
    target = ctx.db.get(User, target_id)
    if target is None or target.role != "staff":
        raise ApiError(400, "VALIDATION_ERROR", "배정 대상은 담당자 계정이어야 합니다.")
    petition.assignee_id, petition.status = target.id, "assigned"
    _touch(petition)
    ctx.db.add(PetitionHistory(petition_id=petition.id, actor_id=user.id, action="assigned", note=""))
    ctx.db.commit()
    return ok(petition_out(petition, history_of(ctx, petition.id)))


def _require_owner_of_work(petition: Petition, user: User) -> None:
    if user.role != "admin" and petition.assignee_id != user.id:
        raise ApiError(403, "FORBIDDEN", "배정된 담당자만 처리할 수 있습니다.")


@router.post("/{petition_id}/status")
def change_status(petition_id: int, body: StatusBody, ctx: Ctx = Depends(get_ctx),
                  user: User = Depends(is_staff)):
    petition = _load(ctx, petition_id)
    _require_owner_of_work(petition, user)
    if body.expected_version != petition.version:
        raise ApiError(409, "VERSION_CONFLICT", "다른 사용자가 먼저 변경했습니다. 새로고침 후 다시 시도해 주세요.")
    if TRANSITIONS.get(petition.status) != body.status:
        raise ApiError(409, "INVALID_TRANSITION", f"{petition.status}에서 {body.status}로 바꿀 수 없습니다.")
    petition.status = body.status
    _touch(petition)
    ctx.db.add(PetitionHistory(petition_id=petition.id, actor_id=user.id, action=body.status, note=body.note))
    ctx.db.commit()
    return ok(petition_out(petition, history_of(ctx, petition.id)))


@router.post("/{petition_id}/reply")
def reply(petition_id: int, body: ReplyBody, ctx: Ctx = Depends(get_ctx),
          user: User = Depends(is_staff)):
    petition = _load(ctx, petition_id)
    _require_owner_of_work(petition, user)
    _touch(petition)
    ctx.db.add(PetitionHistory(petition_id=petition.id, actor_id=user.id, action="reply", note=body.note))
    ctx.db.commit()
    return ok(petition_out(petition, history_of(ctx, petition.id)))
