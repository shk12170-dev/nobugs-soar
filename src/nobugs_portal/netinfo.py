"""출발지 IP. 연결 정보(소켓 주소)만 믿고, X-Forwarded-For 같은 전달 헤더는 쓰지 않는다."""
from __future__ import annotations

import ipaddress

from fastapi import Request


def normalize_ip(raw: str) -> str:
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def client_ip(request: Request) -> str:
    return normalize_ip(request.client.host) if request.client else "unknown"
