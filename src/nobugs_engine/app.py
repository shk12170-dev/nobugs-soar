"""엔진 웹 앱: Graylog 웹훅, 티켓 조회·닫기, 알림 수신함, 간단한 대시보드, 자동 원복 스케줄러."""
from __future__ import annotations

import hmac
import threading
from contextlib import asynccontextmanager
from html import escape

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from .config import EngineSettings
from .engine import Detection, Engine
from .notify import Notifier
from .portal import HttpPortalControl
from .probe import LoopbackProbe
from .store import InvalidTransition, NotFound, Store


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status)


def ticket_out(t, actions=None) -> dict:
    iso = lambda v: v.isoformat() + "Z" if v else None  # noqa: E731
    out = {"id": t.id, "case_id": t.case_id, "group_key": t.group_key, "status": t.status, "src_ip": t.src_ip,
           "username": t.username, "created_at": iso(t.created_at), "updated_at": iso(t.updated_at),
           "detected_at": iso(t.detected_at), "condition_met_at": iso(t.condition_met_at),
           "closed_at": iso(t.closed_at), "close_note": t.close_note}
    if actions is not None:
        out["actions"] = [{"kind": a.kind, "target": a.target, "result": a.result, "applied_verified": a.applied_verified,
                           "effect_verified": a.effect_verified, "active": a.active, "detail": a.detail,
                           "requested_at": iso(a.requested_at), "finished_at": iso(a.finished_at)} for a in actions]
    return out


class Scheduler:
    """일정 간격으로 자동 원복을 점검하는 스레드."""

    def __init__(self, engine: Engine, interval: float) -> None:
        self.engine, self.interval = engine, interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="release-scheduler")

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.engine.release_due()
            except Exception:  # noqa: BLE001 - 점검 하나가 실패해도 스레드는 계속 돈다
                pass

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


def create_engine_app(settings: EngineSettings | None = None, engine: Engine | None = None,
                      store: Store | None = None) -> FastAPI:
    settings = settings or EngineSettings.from_env()
    if engine is None:
        store = store or Store(settings.database_url)
        engine = Engine(settings, store, HttpPortalControl(settings.control_url, settings.control_key,
                                                           settings.control_timeout),
                        LoopbackProbe(settings.probe_base_url), Notifier(store, settings.discord_webhook_url))
    store = engine.store
    scheduler = Scheduler(engine, settings.scheduler_interval_seconds) if settings.scheduler_enabled else None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if scheduler:
            scheduler.start()
        yield
        if scheduler:
            scheduler.stop()

    app = FastAPI(title="nobugs engine", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.engine = engine

    def require_key(x_engine_key: str = Header(default="")) -> None:
        if not settings.engine_key or not hmac.compare_digest(x_engine_key.encode(), settings.engine_key.encode()):
            raise PermissionError

    @app.exception_handler(PermissionError)
    async def _denied(_: Request, __: PermissionError) -> JSONResponse:
        return _error(401, "UNAUTHORIZED", "엔진 키가 없거나 틀립니다.")

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, __: RequestValidationError) -> JSONResponse:
        return _error(400, "VALIDATION_ERROR", "요청 내용을 확인해 주세요.")

    @app.get("/api/v1/health")
    def health():
        return {"data": {"status": "ok", "dry_run_default": settings.default_dry_run}}

    @app.post("/webhook/graylog", dependencies=[Depends(require_key)])
    async def webhook(detection: Detection):
        return {"data": await run_in_threadpool(engine.handle, detection)}

    @app.get("/api/v1/tickets")
    def list_tickets(status: str | None = None, limit: int = 100):
        with store.session() as s:
            return {"data": {"items": [ticket_out(t) for t in store.list(s, status, min(max(limit, 1), 200))]}}

    @app.get("/api/v1/tickets/{ticket_id}")
    def get_ticket(ticket_id: str):
        with store.session() as s:
            try:
                ticket = store.get(s, ticket_id)
            except NotFound:
                return _error(404, "NOT_FOUND", "티켓을 찾을 수 없습니다.")
            return {"data": ticket_out(ticket, store.actions_of(s, ticket_id))}

    @app.post("/api/v1/tickets/{ticket_id}/close", dependencies=[Depends(require_key)])
    def close_ticket(ticket_id: str, note: str = ""):
        with store.session() as s:
            try:
                ticket = store.close(s, ticket_id, note)
            except NotFound:
                return _error(404, "NOT_FOUND", "티켓을 찾을 수 없습니다.")
            except InvalidTransition as exc:
                return _error(409, "INVALID_TRANSITION", str(exc))
            return {"data": ticket_out(ticket)}

    @app.get("/api/v1/notifications")
    def notifications(limit: int = 50):
        items = store.notifications(min(max(limit, 1), 200))
        return {"data": {"items": [{"id": n.id, "created_at": n.created_at.isoformat() + "Z", "content": n.content}
                                   for n in items]}}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        with store.session() as s:
            rows = "".join(
                f"<tr><td><a href='/api/v1/tickets/{escape(t.id)}'>{escape(t.id)}</a></td><td>{escape(t.case_id)}</td>"
                f"<td>{escape(t.src_ip or '-')}</td><td>{escape(t.username or '-')}</td><td>{escape(t.status)}</td>"
                f"<td>{t.updated_at:%H:%M:%S}</td></tr>" for t in store.list(s, None, 50))
        notes = "".join(f"<article><time>{n.created_at:%H:%M:%S} UTC</time><pre>{escape(n.content)}</pre></article>"
                        for n in store.notifications(20))
        return ("<!doctype html><html lang=ko><meta charset=utf-8><title>대응 엔진</title>"
                "<style>body{font:15px system-ui;max-width:980px;margin:24px auto;padding:0 16px}"
                "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:6px;text-align:left}"
                "article{border:1px solid #ccc;border-radius:8px;padding:8px 12px;margin:8px 0}pre{white-space:pre-wrap;margin:4px 0}"
                "</style><h1>대응 엔진</h1><h2>티켓</h2><table><tr><th>번호</th><th>케이스</th><th>출발지</th><th>계정</th>"
                f"<th>상태</th><th>갱신</th></tr>{rows}</table><h2>알림</h2>{notes or '<p>없음</p>'}")

    return app


def engine_factory() -> FastAPI:
    """uvicorn nobugs_engine.app:engine_factory --factory"""
    return create_engine_app()


