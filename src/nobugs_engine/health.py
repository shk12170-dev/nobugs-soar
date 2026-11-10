"""S12 서비스 건강 판정: 요청이 폭주해도 서비스가 멀쩡하면 차단하지 않는다.

표본 하나를 7가지로 분류하고, K개 표본이 모두 '장애 후보'일 때만 `exceeded`(차단 근거)로 본다.
모두 정상이면 `within_baseline`, 섞였거나 계약이 이상하면 `inconclusive` — 둘 다 조치하지 않는다.
"""
from __future__ import annotations

import http.client
import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Protocol

DEGRADED = ("slow_success", "timeout", "network_error", "server_error")


@dataclass(frozen=True)
class Sample:
    ms: float | None
    status: int | None
    body_ok: bool = True
    error: str | None = None          # "timeout" | "network" | None


def classify(sample: Sample, baseline_ms: float) -> str:
    if sample.error == "timeout":
        return "timeout"
    if sample.error:
        return "network_error"
    if sample.status is None:
        return "network_error"
    if sample.status >= 500:
        return "server_error"
    if sample.status != 200:
        return "unexpected_status"           # 4xx·리다이렉트: 장애인지 모른다
    if not sample.body_ok:
        return "invalid_body"                # 200이지만 정상 응답 계약이 아님
    return "slow_success" if sample.ms is not None and sample.ms > baseline_ms else "healthy"


def decide(samples: list[Sample], baseline_ms: float) -> tuple[str, list[str]]:
    """(판정, 표본별 분류). 판정: exceeded | within_baseline | inconclusive."""
    kinds = [classify(s, baseline_ms) for s in samples]
    if not kinds:
        return "inconclusive", kinds
    if all(k in DEGRADED for k in kinds):
        return "exceeded", kinds
    if all(k == "healthy" for k in kinds):
        return "within_baseline", kinds
    return "inconclusive", kinds


class HealthChecker(Protocol):
    def run(self) -> list[Sample]: ...


class HttpHealthChecker:
    """포털 `/api/v1/health`를 간격을 두고 K번 부른다(엔진 자신의 주소에서)."""

    def __init__(self, base_url: str, samples: int = 3, interval: float = 2.0, timeout: float = 5.0) -> None:
        parsed = urllib.parse.urlparse(base_url)
        self.host, self.port = parsed.hostname or "127.0.0.1", parsed.port or 80
        self.samples, self.interval, self.timeout = samples, interval, timeout

    def _one(self) -> Sample:
        started = time.perf_counter()
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            conn.request("GET", "/api/v1/health")
            response = conn.getresponse()
            raw = response.read()
            conn.close()
        except TimeoutError:
            return Sample(None, None, error="timeout")
        except OSError:
            return Sample(None, None, error="network")
        ms = (time.perf_counter() - started) * 1000
        try:
            body_ok = response.status != 200 or json.loads(raw)["data"]["status"] == "ok"
        except (ValueError, KeyError, TypeError):
            body_ok = False
        return Sample(ms, response.status, body_ok)

    def run(self) -> list[Sample]:
        out = []
        for i in range(self.samples):
            out.append(self._one())
            if i < self.samples - 1:
                time.sleep(self.interval)
        return out
