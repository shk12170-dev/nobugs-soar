"""경계 시뮬레이터 앱. 키 인증(X-Boundary-Key) + 허용 출발지(루프백) + 멱등(같은 IP 반복 차단은 changed=False)."""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


class Denied(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class BoundaryState:
    """차단 목록. 파일에 저장해 재시작해도 유지한다."""

    def __init__(self, path: str | None) -> None:
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._ips: set[str] = set()
        if self.path and self.path.exists():
            self._ips = set(json.loads(self.path.read_text(encoding="utf-8")))

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(sorted(self._ips)), encoding="utf-8")

    def block(self, ip: str) -> bool:
        with self._lock:
            changed = ip not in self._ips
            self._ips.add(ip)
            self._save()
            return changed

    def unblock(self, ip: str) -> bool:
        with self._lock:
            changed = ip in self._ips
            self._ips.discard(ip)
            self._save()
            return changed

    def listed(self) -> list[str]:
        with self._lock:
            return sorted(self._ips)


class IpBody(BaseModel):
    ip: str = Field(max_length=45)


def _valid_ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError as exc:
        raise Denied(400, "VALIDATION_ERROR", "IP 주소 형식이 올바르지 않습니다.") from exc


def create_boundary_app(key: str, state_path: str | None = None) -> FastAPI:
    if len(key) < 16:
        raise ValueError("경계 시뮬레이터 키는 16자 이상이어야 합니다.")
    state = BoundaryState(state_path)
    app = FastAPI(title="nobugs boundary (simulated)", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.boundary = state

    def authenticate(request: Request, x_boundary_key: str = Header(default="")) -> None:
        host = request.client.host if request.client else ""
        try:
            local = ipaddress.ip_address(host).is_loopback
        except ValueError:
            local = False
        if not local:
            raise Denied(403, "FORBIDDEN_NETWORK", "허용되지 않은 출발지입니다.")
        if not hmac.compare_digest(x_boundary_key.encode(), key.encode()):
            raise Denied(401, "UNAUTHORIZED", "키가 없거나 틀립니다.")

    @app.exception_handler(Denied)
    async def _denied(_: Request, exc: Denied) -> JSONResponse:
        return JSONResponse({"error": {"code": exc.code, "message": exc.message}}, status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, __: RequestValidationError) -> JSONResponse:
        return JSONResponse({"error": {"code": "VALIDATION_ERROR", "message": "요청 내용을 확인해 주세요."}},
                            status_code=400)

    @app.post("/api/v1/boundary/block", dependencies=[Depends(authenticate)])
    def block(body: IpBody):
        ip = _valid_ip(body.ip)
        return {"data": {"ip": ip, "blocked": True, "changed": state.block(ip), "simulated": True}}

    @app.post("/api/v1/boundary/unblock", dependencies=[Depends(authenticate)])
    def unblock(body: IpBody):
        ip = _valid_ip(body.ip)
        return {"data": {"ip": ip, "blocked": False, "changed": state.unblock(ip), "simulated": True}}

    @app.get("/api/v1/boundary/blocked", dependencies=[Depends(authenticate)])
    def listing():
        return {"data": {"items": state.listed(), "simulated": True}}

    return app


def boundary_factory() -> FastAPI:
    """uvicorn nobugs_boundary.app:boundary_factory --factory"""
    return create_boundary_app(os.environ.get("NB_BOUNDARY_KEY", ""), os.environ.get("NB_BOUNDARY_STATE"))
