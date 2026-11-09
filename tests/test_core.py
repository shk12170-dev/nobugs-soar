"""보안 함수·설정·IP·이벤트 기록의 단위 시험."""
import json
import socket

from nobugs_portal import security
from nobugs_portal.config import Settings
from nobugs_portal.events import EventSink
from nobugs_portal.netinfo import normalize_ip


def test_password_hash_roundtrip_and_wrong_password():
    stored = security.hash_password("correct-horse-battery")
    assert security.verify_password("correct-horse-battery", stored)
    assert not security.verify_password("correct-horse-batterx", stored)


def test_password_hash_uses_random_salt():
    assert security.hash_password("same-password-123") != security.hash_password("same-password-123")


def test_malformed_stored_hash_is_rejected_not_crashing():
    for bad in ("", "plain", "bcrypt$1$2$3$4$5", "scrypt$x$y$z$a$b"):
        assert security.verify_password("whatever-123456", bad) is False


def test_dummy_hash_never_verifies():
    assert security.verify_password("anything-at-all-1", security.DUMMY_HASH) is False


def test_token_helpers():
    token = security.new_token()
    assert len(token) >= 40 and token != security.new_token()
    assert security.token_hash(token) == security.token_hash(token) and len(security.token_hash(token)) == 64
    assert security.safe_equal("abc", "abc") and not security.safe_equal("abc", "abd")


def test_settings_defaults_are_safe():
    s = Settings()
    assert s.response_api_key == "" and s.response_allowed_cidrs == () and not s.gelf_enabled and not s.enable_docs


def test_settings_from_env_parses_values():
    s = Settings.from_env({"NB_RESPONSE_ALLOWED_CIDRS": "127.0.0.0/8, 10.0.0.0/8 ,", "NB_GELF_ENABLED": "true",
                           "NB_LOGIN_RATE_LIMIT": "7", "NB_COOKIE_SECURE": "0", "NB_GELF_PORT": "5000"})
    assert s.response_allowed_cidrs == ("127.0.0.0/8", "10.0.0.0/8")
    assert s.gelf_enabled is True and s.login_rate_limit == 7 and s.cookie_secure is False and s.gelf_port == 5000


def test_normalize_ip_maps_ipv4_mapped_ipv6():
    assert normalize_ip("::ffff:203.0.113.5") == "203.0.113.5"
    assert normalize_ip("203.0.113.5") == "203.0.113.5"
    assert normalize_ip("2001:db8::1") == "2001:db8::1"
    assert normalize_ip("not-an-ip") == "not-an-ip"


def test_event_is_written_as_json_line_with_rule(tmp_path):
    sink = EventSink(Settings(event_log_path=str(tmp_path / "e.jsonl")))
    sink.emit("auth.login_failed", outcome="failure", status=401, src_ip="203.0.113.9", username="citizen1")
    sink.emit("web.not_found", outcome="denied", status=404, src_ip="203.0.113.9", path="/wp-admin")
    lines = [json.loads(x) for x in (tmp_path / "e.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [x["rule"] for x in lines] == ["login-bruteforce", "web-scan"]
    assert lines[0]["username"] == "citizen1" and lines[0]["asset_id"] == "nobugs-portal"
    assert {"event_id", "timestamp", "event_type", "outcome", "status", "src_ip"} <= set(lines[0])


def test_gelf_is_off_by_default_and_sends_udp_when_enabled(tmp_path):
    off = EventSink(Settings(event_log_path=str(tmp_path / "a.jsonl")))
    assert off._sock is None  # noqa: SLF001
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(3)
    port = receiver.getsockname()[1]
    on = EventSink(Settings(event_log_path=str(tmp_path / "b.jsonl"), gelf_enabled=True, gelf_port=port))
    on.emit("auth.login_failed", outcome="failure", status=401, src_ip="203.0.113.9", username="citizen1")
    message = json.loads(receiver.recvfrom(65535)[0])
    receiver.close()
    assert message["version"] == "1.1" and message["short_message"] == "auth.login_failed"
    assert message["_rule"] == "login-bruteforce" and message["_src_ip"] == "203.0.113.9"


def test_gelf_failure_does_not_break_the_service(tmp_path):
    sink = EventSink(Settings(event_log_path=str(tmp_path / "c.jsonl"), gelf_enabled=True,
                              gelf_host="256.256.256.256", gelf_port=9))
    sink.emit("web.request", outcome="observed", status=200, src_ip="203.0.113.9")  # 예외 없이 끝나야 한다
    assert (tmp_path / "c.jsonl").exists()
