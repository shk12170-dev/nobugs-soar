"""syslog 중계기 시험: syslog→GELF 변환, GELF/TCP 송신, 수신 루프가 GELF로 넣는지."""
from __future__ import annotations

import json
import socket
import threading
import time

from nobugs_tools import syslog_relay


def test_parse_keeps_message_and_uses_sender_ip_as_host():
    # pfSense식(호스트네임 없음): <PRI>만 떼고 나머지는 short_message, host는 보낸 IP
    g = syslog_relay.parse_syslog_to_gelf(b"<78>Nov 11 02:27:00 /usr/sbin/cron[2359]: (root) CMD", "172.16.50.2")
    assert g["host"] == "172.16.50.2"
    assert g["short_message"] == "Nov 11 02:27:00 /usr/sbin/cron[2359]: (root) CMD"
    assert g["version"] == "1.1"
    assert g["_source_kind"] == "pfsense-syslog"


def test_parse_decodes_severity_from_pri():
    # PRI 134 = facility 16*8 + severity 6 -> level 6
    assert syslog_relay.parse_syslog_to_gelf(b"<134>hello", "10.0.0.1")["level"] == 6
    # PRI 11 -> severity 3
    assert syslog_relay.parse_syslog_to_gelf(b"<11>oops", "10.0.0.1")["level"] == 3


def test_parse_handles_a_line_without_pri():
    g = syslog_relay.parse_syslog_to_gelf(b"no pri here", "10.0.0.1")
    assert g["short_message"] == "no pri here"
    assert g["level"] == 6


def test_parse_empty_payload_is_not_blank():
    assert syslog_relay.parse_syslog_to_gelf(b"<13>", "10.0.0.1")["short_message"] == "(empty)"


def _recv_one_gelf(server: socket.socket) -> dict:
    conn, _ = server.accept()
    buf = b""
    while b"\x00" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    conn.close()
    return json.loads(buf.split(b"\x00", 1)[0].decode("utf-8"))


def test_gelf_tcp_sender_sends_null_delimited_json():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    got: dict = {}
    t = threading.Thread(target=lambda: got.update(_recv_one_gelf(server)))
    t.start()
    sender = syslog_relay.GelfTcpSender("127.0.0.1", port)
    assert sender.send({"version": "1.1", "host": "h", "short_message": "hi"}) is True
    t.join(timeout=3)
    sender.close()
    server.close()
    assert got["short_message"] == "hi"


def test_serve_receives_udp_and_forwards_one_gelf_over_tcp():
    # GELF 종단(TCP 서버)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(5)
    gelf_port = server.getsockname()[1]

    # 중계기가 쓸 UDP 수신 포트
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    listen_port = probe.getsockname()[1]
    probe.close()

    got: dict = {}
    recv_thread = threading.Thread(target=lambda: got.update(_recv_one_gelf(server)))
    recv_thread.start()

    serve_thread = threading.Thread(target=lambda: syslog_relay.serve(
        "127.0.0.1", listen_port, "127.0.0.1", gelf_port, max_packets=1, quiet=True))
    serve_thread.start()

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    deadline = time.time() + 5
    while not got and time.time() < deadline:
        sender.sendto(b"<134>Nov 11 02:27:00 pfSense filterlog: block in", ("127.0.0.1", listen_port))
        time.sleep(0.2)
    sender.close()
    serve_thread.join(timeout=3)
    recv_thread.join(timeout=3)
    server.close()

    assert got.get("host") == "127.0.0.1"
    assert "filterlog: block in" in got.get("short_message", "")
