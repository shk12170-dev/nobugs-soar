"""포털 대응 API 클라이언트.

결과를 세 가지로 나눈다: 성공 / 확정 거절(4xx, PortalError) / 불확실(시간 초과·연결 실패·5xx, PortalUncertain).
불확실한 결과는 조치가 실제로 적용됐는지 모르는 상태이므로, 호출한 쪽이 차단 목록을 다시 조회해 대조해야 한다.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Protocol


class PortalError(Exception):
    """포털이 요청을 확정적으로 거절했다(4xx). 조치는 일어나지 않았다."""


class PortalUncertain(Exception):
    """응답을 받지 못했거나 서버 오류다. 조치가 적용됐는지 알 수 없다."""


class PortalControl(Protocol):
    def block_ip(self, ip: str, idempotency_key: str) -> dict: ...
    def unblock_ip(self, ip: str, idempotency_key: str) -> dict: ...
    def blocked_ips(self) -> set[str]: ...


class HttpPortalControl:
    def __init__(self, base_url: str, key: str, timeout: float = 5.0) -> None:
        self.base = base_url.rstrip("/")
        self.key = key
        self.timeout = timeout

    def _call(self, method: str, path: str, body: dict | None = None, idem: str | None = None) -> dict:
        headers = {"X-Response-Key": self.key, "Content-Type": "application/json"}
        if idem:
            headers["Idempotency-Key"] = idem
        request = urllib.request.Request(self.base + path, method=method, headers=headers,
                                         data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.load(response)["data"]
        except urllib.error.HTTPError as exc:
            if 400 <= exc.code < 500:
                raise PortalError(f"{exc.code} {exc.read()[:160].decode('utf-8', 'replace')}") from exc
            raise PortalUncertain(f"서버 오류 {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as exc:
            raise PortalUncertain(f"응답 없음: {type(exc).__name__}") from exc

    def block_ip(self, ip: str, idempotency_key: str) -> dict:
        return self._call("POST", "/api/v1/response/ips/block", {"ip": ip}, idempotency_key)

    def unblock_ip(self, ip: str, idempotency_key: str) -> dict:
        return self._call("POST", "/api/v1/response/ips/unblock", {"ip": ip}, idempotency_key)

    def blocked_ips(self) -> set[str]:
        return {item["ip"] for item in self._call("GET", "/api/v1/response/ips")["items"]}
