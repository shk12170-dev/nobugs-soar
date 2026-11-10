"""효과 확인 프로브: 차단이 '목록에 있다'가 아니라 '실제로 막힌다'를 확인한다.

공격 출발지 주소로 포털에 요청을 보내 403이면 차단됨, 200이면 접근 가능으로 본다. 이 PC에서는 출발지를
루프백 주소(127.x)로 지정할 수 있는 경우에만 확인할 수 있고, 그 밖의 주소는 확인 불가(None)로 둔다.
확인 불가를 '성공'으로 처리하지 않는다.
"""
from __future__ import annotations

import http.client
import ipaddress
import urllib.parse
from typing import Protocol


class EffectProbe(Protocol):
    def is_blocked(self, ip: str) -> bool | None: ...
    def is_reachable(self, ip: str) -> bool | None: ...


class NullProbe:
    def is_blocked(self, ip: str) -> bool | None:
        return None

    def is_reachable(self, ip: str) -> bool | None:
        return None


class LoopbackProbe:
    def __init__(self, base_url: str, timeout: float = 3.0) -> None:
        parsed = urllib.parse.urlparse(base_url)
        self.host, self.port, self.timeout = parsed.hostname or "127.0.0.1", parsed.port or 80, timeout

    def _status(self, ip: str) -> int | None:
        try:
            if not ipaddress.ip_address(ip).is_loopback:
                return None
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout, source_address=(ip, 0))
            conn.request("GET", "/api/v1/health")
            status = conn.getresponse().status
            conn.close()
            return status
        except (ValueError, OSError):
            return None

    def is_blocked(self, ip: str) -> bool | None:
        status = self._status(ip)
        return None if status is None else status == 403

    def is_reachable(self, ip: str) -> bool | None:
        status = self._status(ip)
        return None if status is None else status == 200
