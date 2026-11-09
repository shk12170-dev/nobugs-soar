"""시민 민원: 신청·내 목록·상세. 본인 민원만 볼 수 있다(담당자·관리자는 전체)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from ..deps import Ctx, csrf_guard, get_ctx, is_citizen, ok, require_login
from ..errors import ApiError
from ..models import Petition, PetitionHistory, User, utcnow

router = APIRouter(prefix="/api/v1/petitions", tags=["petitions"], dependencies=[Depends(csrf_guard)])

CATEGORIES = ("road", "environment", "welfare", "traffic", "etc")


class PetitionBody(BaseModel):
    category: str = Field(pattern="^(" + "|".join(CATEGORIES) + ")$")
    title: str = Field(min_length=2, max_length=100)
    body: str = Field(min_length=5, max_length=2000)


def petition_out(p: Petition, history: list[PetitionHistory] | None = None) -> dict:
    out = {"id": p.id, "owner_id": p.owner_id, "category": p.category, "title": p.title, "body": p.body,
           "status": p.status, "assignee_id": p.assignee_id, "version": p.version,
           "created_at": p.created_at.isoformat(), "updated_at": p.updated_at.isoformat()}
    if history is not None:
        out["history"] = [{"action": h.action, "note": h.note, "actor_id": h.actor_id,
                           "created_at": h.created_at.isoformat()} for h in history]
    return out


def history_of(ctx: Ctx, petition_id: int) -> list[PetitionHistory]:
    return list(ctx.db.scalars(select(PetitionHistory).where(PetitionHistory.petition_id == petition_id)
                               .order_by(PetitionHistory.id)))


@router.post("")
def create(body: PetitionBody, ctx: Ctx = Depends(get_ctx), user: User = Depends(is_citizen)):
    now = utcnow()
    petition = Petition(owner_id=user.id, category=body.category, title=body.title, body=body.body,
                        status="received", version=1, created_at=now, updated_at=now)
    ctx.db.add(petition)
    ctx.db.flush()
    ctx.db.add(PetitionHistory(petition_id=petition.id, actor_id=user.id, action="created", note=""))
    ctx.db.commit()
    return ok(petition_out(petition, history_of(ctx, petition.id)), 201)


@router.get("/mine")
def mine(ctx: Ctx = Depends(get_ctx), user: User = Depends(require_login)):
    rows = ctx.db.scalars(select(Petition).where(Petition.owner_id == user.id).order_by(Petition.id.desc()))
    return ok({"items": [petition_out(p) for p in rows]})


@router.get("/{petition_id}")
def detail(petition_id: int, ctx: Ctx = Depends(get_ctx), user: User = Depends(require_login)):
    petition = ctx.db.get(Petition, petition_id)
    # 남의 민원은 존재 여부도 알 수 없게 404로 답한다
    if petition is None or (user.role == "citizen" and petition.owner_id != user.id):
        raise ApiError(404, "NOT_FOUND", "민원을 찾을 수 없습니다.")
    return ok(petition_out(petition, history_of(ctx, petition.id)))
