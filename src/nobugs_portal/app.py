"""일반 포털 앱 조립. 대응 API는 여기에 마운트하지 않는다(control.py의 별도 앱)."""
from __future__ import annotations

from fastapi import FastAPI, Request
from starlette.concurrency import run_in_threadpool

from . import web
from .config import Settings
from .deps import ok
from .errors import error_response, install_error_handlers
from .netinfo import client_ip
from .routers import admin, auth, petitions, staff
from .services import is_blocked
from .state import AppState

# 외부 스크립트·스타일·이미지는 같은 출처만 허용한다(빌드 결과에 인라인 스크립트가 없다)
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
                               "form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def create_public_app(settings: Settings | None = None, state: AppState | None = None) -> FastAPI:
    state = state or AppState.build(settings or Settings.from_env())
    docs = state.settings.enable_docs
    app = FastAPI(title="nobugs portal", docs_url="/docs" if docs else None, redoc_url=None,
                  openapi_url="/openapi.json" if docs else None)
    app.state.nb = state
    install_error_handlers(app)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        ip = client_ip(request)
        request.state.client_ip = ip

        def blocked() -> bool:
            with state.db.session() as db:
                return is_blocked(db, ip)

        # 차단 판정이 가장 먼저 일어난다
        if await run_in_threadpool(blocked):
            await run_in_threadpool(lambda: state.events.emit(
                "web.blocked", outcome="denied", status=403, src_ip=ip, path=request.url.path[:120]))
            return error_response(403, "IP_BLOCKED", "접근이 차단된 주소입니다.")
        response = await call_next(request)
        path = request.url.path[:120]

        def record() -> None:
            state.events.emit("web.request", outcome="observed", status=response.status_code, src_ip=ip,
                              path=path, method=request.method)
            if response.status_code == 404:
                state.events.emit("web.not_found", outcome="denied", status=404, src_ip=ip, path=path)
            if path.startswith("/api/v1/admin") and response.status_code in (401, 403):
                state.events.emit("admin.auth_failed", outcome="denied", status=response.status_code,
                                  src_ip=ip, path=path)
        await run_in_threadpool(record)
        response.headers.update(SECURITY_HEADERS)
        return response

    @app.get("/api/v1/health")
    def health():
        return ok({"status": "ok"})

    for module in (auth, petitions, staff, admin):
        app.include_router(module.router)
    app.include_router(web.router)
    return app


def public_factory() -> FastAPI:
    """uvicorn nobugs_portal.app:public_factory --factory"""
    return create_public_app(Settings.from_env())
