"""빌드된 프론트(web/dist)를 서빙한다. 파일 접근마다 `web.file_access` 이벤트에 파일 키를 남긴다.

파일 키는 웹 루트 기준 상대 경로다(`index.html`, `assets/app.js`, `favicon.svg`). 홈페이지와 화면 경로(/login 등)는
모두 `index.html`로 기록한다. 이 값이 변조 탐지(S7)에서 "같은 파일에 대한 접근"을 짝짓는 기준이다.
정해진 경로 말고는 404로 두어, 임의 경로 요청이 웹 스캔 이벤트로 잡히게 한다.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse

from .errors import ApiError
from .netinfo import client_ip

router = APIRouter(tags=["web"], include_in_schema=False)


def _dist(request: Request) -> Path:
    return Path(request.app.state.nb.settings.frontend_dist).resolve()


def _record(request: Request, file_key: str) -> None:
    request.app.state.nb.events.emit("web.file_access", outcome="success", status=200,
                                     src_ip=client_ip(request), file_key=file_key)


def _serve(request: Request, relative: str):
    base = _dist(request)
    target = (base / relative).resolve()
    if not target.is_relative_to(base) or not target.is_file():
        raise ApiError(404, "NOT_FOUND", "요청한 파일을 찾을 수 없습니다.")
    _record(request, target.relative_to(base).as_posix())
    headers = {"Cache-Control": "no-cache"} if relative == "index.html" else None
    return FileResponse(target, headers=headers)


def _index(request: Request):
    if not (_dist(request) / "index.html").is_file():
        raise ApiError(503, "FRONTEND_NOT_BUILT", "프론트가 빌드되지 않았습니다(web/에서 npm run build).")
    return _serve(request, "index.html")


@router.get("/")
@router.get("/login")
@router.get("/register")
@router.get("/staff")
@router.get("/admin")
@router.get("/petitions")
def spa_root(request: Request):
    return _index(request)


@router.get("/petitions/{rest:path}")
@router.get("/staff/{rest:path}")
@router.get("/admin/{rest:path}")
def spa_nested(request: Request, rest: str):
    return _index(request)


@router.get("/index.html")
def index_file(request: Request):
    return _index(request)


@router.get("/favicon.svg")
def favicon(request: Request):
    return _serve(request, "favicon.svg")


@router.get("/assets/{name:path}")
def asset(request: Request, name: str):
    return _serve(request, f"assets/{name}")
