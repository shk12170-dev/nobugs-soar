"""구조화 이벤트 기록. JSONL 파일에 항상 남기고, 설정하면 Graylog(GELF, UDP)로도 보낸다.

비밀번호·토큰·민원 본문 같은 값은 이벤트에 넣지 않는다.
`rule` 필드는 Graylog 이벤트 정의가 조건에 쓰는 분류 이름이다.
"""
from __future__ import annotations

import datetime as dt
import json
import socket
import threading
import uuid
from pathlib import Path
from typing import Any

from .config import Settings

# 이벤트 종류 -> 탐지 규칙에서 쓰는 분류
RULES = {
    "auth.login_failed": "login-bruteforce",
    "auth.login_succeeded": "login-success",
    "web.not_found": "web-scan",
    "web.request": "request-observed",
    "web.file_access": "file-access",
}


class EventSink:
    def __init__(self, settings: Settings) -> None:
        self._asset_id = settings.asset_id
        self._path = Path(settings.event_log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._gelf_addr = (settings.gelf_host, settings.gelf_port) if settings.gelf_enabled else None
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if self._gelf_addr else None

    def emit(self, event_type: str, *, outcome: str, status: int, src_ip: str,
             username: str | None = None, **extra: Any) -> dict[str, Any]:
        event: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds"),
            "event_type": event_type,
            "rule": RULES.get(event_type, event_type),
            "outcome": outcome,
            "status": status,
            "src_ip": src_ip,
            "username": username,
            "asset_id": self._asset_id,
            **extra,
        }
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        self._send_gelf(event)
        return event

    def _send_gelf(self, event: dict[str, Any]) -> None:
        if self._sock is None or self._gelf_addr is None:
            return
        message = {"version": "1.1", "host": self._asset_id, "short_message": event["event_type"],
                   "timestamp": dt.datetime.fromisoformat(event["timestamp"]).timestamp()}
        message.update({f"_{k}": v for k, v in event.items() if v is not None and k != "timestamp"})
        try:
            self._sock.sendto(json.dumps(message, ensure_ascii=False).encode(), self._gelf_addr)
        except OSError:
            pass  # 수집 실패가 서비스를 막으면 안 된다
