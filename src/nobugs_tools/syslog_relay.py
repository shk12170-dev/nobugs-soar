"""호스트 syslog 중계기: 외부(pfSense VM)에서 온 UDP syslog를 받아 Graylog로 GELF/TCP로 넣는다.

왜 이렇게 하나:
- Docker Desktop(WSL2)은 UDP 게시 포트의 전달이 매우 불안정하다. 외부 호스트發 UDP는 컨테이너로 거의
  안 넘어가고, 루프백으로 되쏴도 드롭된다(실측: 20건 중 0건 도착). 반면 호스트의 네이티브 UDP 소켓은
  외부 패킷을 정상 수신하고, Docker의 TCP 전달은 신뢰성 있다.
- 그래서 이 중계기가 호스트 네이티브 소켓으로 172.16.50.100:1514에서 syslog를 받아(SO_REUSEADDR는
  Windows에서 외부 수신을 막으므로 쓰지 않는다), 각 줄을 GELF로 바꿔 이미 검증된 GELF TCP 입력
  (127.0.0.1:12301)으로 보낸다. GELF의 host를 보낸 IP(pfSense 172.16.50.2)로 넣어, Graylog의 source도
  pfSense로 제대로 찍힌다(pfSense syslog는 호스트네임 필드가 없어 UDP 출발지로만 구분된다).

사용: python -m nobugs_tools.syslog_relay     # 172.16.50.100:1514 -> GELF/TCP 127.0.0.1:12301
      (수신 주소는 .env의 NB_SYSLOG_BIND, 전달 포트는 NB_SYSLOG_GELF_PORT)
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time


def parse_syslog_to_gelf(data: bytes, src_ip: str) -> dict:
    """RFC3164 syslog 한 줄을 GELF 메시지로 바꾼다.

    `<PRI>`만 떼어 severity를 level로 넘기고 나머지는 short_message로 둔다(pfSense는 호스트네임 필드가
    없어 날짜 뒤 바로 태그가 온다). host는 보낸 IP로 넣어 Graylog의 source가 pfSense가 되게 한다.
    """
    text = data.decode("latin1", errors="replace").rstrip("\n")
    level = 6  # 기본 info
    msg = text
    if text.startswith("<"):
        close = text.find(">")
        if 0 < close <= 5:
            try:
                pri = int(text[1:close])
                level = pri & 0x7
                msg = text[close + 1:]
            except ValueError:
                pass
    return {
        "version": "1.1",
        "host": src_ip,
        "short_message": msg or "(empty)",
        "level": level,
        "_source_kind": "pfsense-syslog",
        "_relay": "nobugs-syslog-relay",
    }


class GelfTcpSender:
    """GELF TCP(널 구분) 송신기. 연결이 끊기면 다음 전송 때 다시 잇는다."""

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self._sock: socket.socket | None = None

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        self._sock = s
        return s

    def send(self, gelf: dict) -> bool:
        payload = json.dumps(gelf, ensure_ascii=False).encode("utf-8") + b"\x00"
        for _ in range(2):  # 끊겨 있으면 한 번 다시 잇고 재시도
            try:
                sock = self._sock or self._connect()
                sock.sendall(payload)
                return True
            except OSError:
                self.close()
        return False

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


def serve(listen_host: str, listen_port: int, gelf_host: str, gelf_port: int,
          *, max_packets: int | None = None, quiet: bool = False,
          sender: GelfTcpSender | None = None) -> int:
    """중계를 시작한다. max_packets가 주어지면 그만큼만 전달하고 멈춘다(시험용)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # SO_REUSEADDR 쓰지 않는다(외부 수신 보장)
    listener.bind((listen_host, listen_port))
    listener.settimeout(1.0)
    sender = sender or GelfTcpSender(gelf_host, gelf_port)
    if not quiet:
        print(f"syslog 중계기: {listen_host}:{listen_port} -> GELF/TCP {gelf_host}:{gelf_port} (Ctrl+C로 종료)",
              flush=True)
    count = 0
    try:
        while max_packets is None or count < max_packets:
            try:
                data, addr = listener.recvfrom(65535)
            except TimeoutError:
                continue
            if data and sender.send(parse_syslog_to_gelf(data, addr[0])):
                count += 1
    except KeyboardInterrupt:
        pass
    finally:
        listener.close()
        sender.close()
    return count


def main(argv: list[str] | None = None) -> int:
    env = os.environ
    parser = argparse.ArgumentParser(prog="nobugs_tools.syslog_relay")
    parser.add_argument("--listen-host", default=env.get("NB_SYSLOG_BIND", "172.16.50.100"),
                        help="외부(pfSense)에서 오는 syslog를 받을 호스트 주소(VMnet 호스트 IP)")
    parser.add_argument("--listen-port", type=int, default=int(env.get("NB_SYSLOG_PORT", "1514")))
    parser.add_argument("--gelf-host", default="127.0.0.1")
    parser.add_argument("--gelf-port", type=int, default=int(env.get("NB_SYSLOG_GELF_PORT", "12301")),
                        help="Graylog GELF TCP 입력의 호스트 포트(docker-compose 매핑)")
    parser.add_argument("--max-packets", type=int, default=None, help="이 수만큼만 전달하고 종료(시험용)")
    args = parser.parse_args(argv)
    if args.listen_host in ("127.0.0.1", "0.0.0.0", ""):
        print("경고: --listen-host가 루프백/와일드카드입니다. pfSense가 닿는 VMnet 호스트 주소(예: 172.16.50.100)를 "
              "쓰세요(.env의 NB_SYSLOG_BIND).", file=sys.stderr)
    while True:
        try:
            serve(args.listen_host, args.listen_port, args.gelf_host, args.gelf_port)
            break
        except OSError as exc:  # 바인딩 실패 등은 잠깐 쉬고 다시(일시적 포트 점유 대비)
            print(f"중계기 오류, 3초 뒤 재시도: {exc}", file=sys.stderr, flush=True)
            time.sleep(3)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
