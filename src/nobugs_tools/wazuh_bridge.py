"""Wazuh 매니저의 FIM(파일 변조) 경보를 Graylog로 넘기는 다리.

인덱서·대시보드는 쓰지 않는다. 매니저가 로컬에 쓰는 `alerts.json`을 이 도구가 직접 따라 읽고(tail),
웹 루트 밑의 syscheck 경보만 골라 기준본과 다를 때만(노이즈를 줄이려고) `rule:tamper-signal` GELF를
Graylog로 보낸다. 실제 변조인지 최종 판단은 대응 엔진이 포털에서 다시 확인한다(여기서 하는 확인은 참고용).

사용: python -m nobugs_tools.wazuh_bridge --alerts-log infra/wazuh/logs/alerts/alerts.json \
      --agent-prefix /nobugs/web-root --web-root web/dist --baseline-dir instance/baseline
"""
from __future__ import annotations

import argparse
import json
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nobugs_portal import baseline

SYSCHECK_EVENTS = {"added", "modified", "deleted"}


def file_key_of(alert: dict[str, Any], agent_prefix: str) -> str | None:
    """syscheck 경보이고 경로가 감시 대상(웹 루트) 밑이면 파일 키(상대 경로)를, 아니면 None을 돌려준다."""
    groups = alert.get("rule", {}).get("groups", [])
    if "syscheck" not in groups:
        return None
    sc = alert.get("syscheck", {})
    if sc.get("event") not in SYSCHECK_EVENTS:
        return None
    path = sc.get("path", "")
    prefix = agent_prefix.rstrip("/") + "/"
    if not path.startswith(prefix):
        return None
    return path[len(prefix):]


class AlertTailer:
    """`alerts.json`(한 줄에 경보 하나)을 따라 읽는다. 로그 회전(파일이 작아짐)을 감지해 처음부터 다시 읽는다."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._offset = 0

    def poll(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        size = self.path.stat().st_size
        if size < self._offset:          # 회전됨(파일이 새로 시작)
            self._offset = 0
        alerts = []
        with self.path.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(self._offset)
            for line in f:
                if not line.endswith("\n"):   # 아직 다 쓰이지 않은 마지막 줄은 다음 polling에
                    break
                self._offset += len(line.encode("utf-8", errors="replace"))
                line = line.strip()
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return alerts


def make_gelf_sender(host: str, port: int, asset_id: str) -> Callable[[str], None]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(file_key: str) -> None:
        message = {"version": "1.1", "host": "wazuh-bridge", "short_message": "tamper.signal",
                   "_rule": "tamper-signal", "_event_type": "tamper.signal", "_outcome": "detected",
                   "_asset_id": asset_id, "_file_key": file_key}
        try:
            sock.sendto(json.dumps(message, ensure_ascii=False).encode(), (host, port))
        except OSError:
            pass  # 전송 실패가 다리를 멈추면 안 된다(다음 주기에 다시 시도될 수 있음)

    return send


def bridge_once(tailer: AlertTailer, agent_prefix: str, web_root: str, baseline_dir: str,
                send: Callable[[str], None]) -> list[str]:
    """새 경보를 한 번 처리한다. 기준본과 실제로 다른 파일 키 목록을 돌려준다(보낸 것)."""
    forwarded = []
    for alert in tailer.poll():
        file_key = file_key_of(alert, agent_prefix)
        if file_key is None:
            continue
        state = baseline.file_state(web_root, baseline_dir, file_key)
        if state["matches_baseline"]:
            continue    # 기준본과 같은 변경(예: 정상 재배포)은 변조 신호로 보지 않는다
        send(file_key)
        forwarded.append(file_key)
    return forwarded


def run(alerts_log: str, agent_prefix: str, web_root: str, baseline_dir: str, gelf_host: str, gelf_port: int,
       asset_id: str, interval: float = 2.0) -> None:
    tailer = AlertTailer(alerts_log)
    send = make_gelf_sender(gelf_host, gelf_port, asset_id)
    print(f"wazuh-bridge 시작: {alerts_log} 감시, 웹 루트 접두사 {agent_prefix} -> Graylog {gelf_host}:{gelf_port}")
    while True:
        for file_key in bridge_once(tailer, agent_prefix, web_root, baseline_dir, send):
            print(f"변조 신호 전달: {file_key}")
        time.sleep(interval)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_tools.wazuh_bridge")
    parser.add_argument("--alerts-log", default="infra/wazuh/logs/alerts/alerts.json")
    parser.add_argument("--agent-prefix", default="/nobugs/web-root")
    parser.add_argument("--web-root", default="web/dist")
    parser.add_argument("--baseline-dir", default="instance/baseline")
    parser.add_argument("--gelf-host", default="127.0.0.1")
    parser.add_argument("--gelf-port", type=int, default=12301)
    parser.add_argument("--asset-id", default="nobugs-portal")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args(argv)
    run(args.alerts_log, args.agent_prefix, args.web_root, args.baseline_dir, args.gelf_host, args.gelf_port,
       args.asset_id, args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
