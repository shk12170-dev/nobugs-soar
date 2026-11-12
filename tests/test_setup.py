"""원클릭 설치 도구(M7)의 시험. 실제 docker·npm은 부르지 않고 순서·분기·표시만 확인한다."""
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from nobugs_tools import setup

# ---- _docker_status / _graylog_reachable ----


def test_docker_status_reports_the_container_state(monkeypatch):
    def fake_run(cmd, **kwargs):
        assert cmd[:2] == ["docker", "inspect"]
        return subprocess.CompletedProcess(cmd, 0, stdout="running\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert setup._docker_status("nobugs-soc-graylog-1") == "running"


def test_docker_status_is_none_when_docker_is_unreachable(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise OSError("docker daemon not running")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert setup._docker_status("nobugs-soc-graylog-1") == "없음"


class FakeLB(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_graylog_http():
    server = HTTPServer(("127.0.0.1", 0), FakeLB)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_graylog_reachable_is_true_when_it_answers(fake_graylog_http):
    assert setup._graylog_reachable(fake_graylog_http) is True


def test_graylog_reachable_is_false_when_nothing_is_listening():
    assert setup._graylog_reachable("http://127.0.0.1:1") is False


# ---- print_status ----


def test_print_status_shows_every_check(capsys):
    status = {"env_file": True, "web_dist": False, "baseline": True,
             "containers": {"nobugs-soc-graylog-1": "running"}, "graylog_reachable": True}
    setup.print_status(status)
    out = capsys.readouterr().out
    assert "확인" in out and "미확인" in out and "nobugs-soc-graylog-1" in out and "running" in out
    assert "nobugs_tools.run portal" in out and "nobugs_tools.run engine" in out   # 다음 단계 안내


# ---- relay_bind (pfSense 중계기 기동 판단) ----


@pytest.mark.parametrize("bind", ["127.0.0.1", "0.0.0.0", "localhost", "", None])
def test_relay_bind_is_none_for_loopback_or_unset(bind):
    env = {"NB_SYSLOG_BIND": bind} if bind is not None else {}
    assert setup.relay_bind(env) is None


def test_relay_bind_returns_the_vmnet_address_when_configured():
    assert setup.relay_bind({"NB_SYSLOG_BIND": "172.16.50.100"}) == "172.16.50.100"


def test_print_status_names_the_relay_when_a_vmnet_bind_is_set(capsys):
    status = {"env_file": True, "web_dist": True, "baseline": True, "containers": {},
              "graylog_reachable": True, "relay_bind": "172.16.50.100"}
    setup.print_status(status)
    out = capsys.readouterr().out
    assert "172.16.50.100:1514" in out and "중계기" in out


def test_print_status_says_relay_skipped_without_a_vmnet_bind(capsys):
    status = {"env_file": True, "web_dist": True, "baseline": True, "containers": {},
              "graylog_reachable": True, "relay_bind": None}
    setup.print_status(status)
    assert "생략" in capsys.readouterr().out


# ---- step_seed_baseline / step_seed_demo (subprocess 흉내) ----


def test_step_seed_baseline_skips_when_frontend_is_not_built(monkeypatch, tmp_path):
    monkeypatch.setattr(setup, "ROOT", tmp_path)
    assert setup.step_seed_baseline() is False


def test_step_seed_demo_returns_false_when_already_seeded(monkeypatch):
    monkeypatch.setattr(setup, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr=""))
    assert setup.step_seed_demo() is False


def test_step_seed_demo_returns_true_on_success(monkeypatch):
    monkeypatch.setattr(setup, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr=""))
    assert setup.step_seed_demo() is True


# ---- run_setup 순서·분기 ----


def test_run_setup_skips_docker_steps_when_requested(monkeypatch):
    calls = []
    monkeypatch.setattr(setup, "step_env", lambda: calls.append("env"))
    monkeypatch.setattr(setup, "step_docker_up", lambda with_wazuh: calls.append(("docker", with_wazuh)))
    monkeypatch.setattr(setup, "step_wait_graylog", lambda: calls.append("wait"))
    monkeypatch.setattr(setup, "step_seed_baseline", lambda: calls.append("baseline"))
    monkeypatch.setattr(setup, "step_seed_demo", lambda: calls.append("demo"))
    monkeypatch.setattr(setup, "step_graylog_setup", lambda live: calls.append(("graylog", live)))
    monkeypatch.setattr(setup, "status_report", lambda with_wazuh: {"env_file": True, "web_dist": True,
                                                                    "baseline": True, "containers": {},
                                                                    "graylog_reachable": True})
    monkeypatch.setattr(setup, "print_status", lambda status: calls.append("printed"))

    setup.run_setup(with_wazuh=True, skip_docker=True, live=True)

    assert calls == ["env", "baseline", "demo", ("graylog", True), "printed"]


def test_run_setup_brings_up_docker_and_waits_when_not_skipped(monkeypatch):
    calls = []
    monkeypatch.setattr(setup, "step_env", lambda: None)
    monkeypatch.setattr(setup, "step_docker_up", lambda with_wazuh: calls.append(("docker", with_wazuh)))
    monkeypatch.setattr(setup, "step_wait_graylog", lambda: calls.append("wait"))
    monkeypatch.setattr(setup, "step_seed_baseline", lambda: None)
    monkeypatch.setattr(setup, "step_seed_demo", lambda: None)
    monkeypatch.setattr(setup, "step_graylog_setup", lambda live: None)
    monkeypatch.setattr(setup, "status_report", lambda with_wazuh: {"env_file": True, "web_dist": True,
                                                                    "baseline": True, "containers": {},
                                                                    "graylog_reachable": True})
    monkeypatch.setattr(setup, "print_status", lambda status: None)

    setup.run_setup(with_wazuh=False, skip_docker=False, live=False)

    assert calls == [("docker", False), "wait"]


def test_step_docker_up_raises_a_readable_error_on_failure(monkeypatch):
    monkeypatch.setattr(setup, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, stdout="", stderr=""))
    with pytest.raises(setup.SetupError):
        setup.step_docker_up(with_wazuh=False)


def test_step_docker_up_includes_wazuh_services_only_when_asked(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(setup, "run", fake_run)
    setup.step_docker_up(with_wazuh=True)
    assert "wazuh-manager" in seen["cmd"] and "wazuh-agent" in seen["cmd"]

    setup.step_docker_up(with_wazuh=False)
    assert "wazuh-manager" not in seen["cmd"]


def test_status_report_follows_the_compose_project_name(monkeypatch):
    seen = []
    monkeypatch.setattr(setup, "_docker_status", lambda name: seen.append(name) or "running")
    monkeypatch.setattr(setup, "_graylog_reachable", lambda url: True)
    monkeypatch.delenv("COMPOSE_PROJECT_NAME", raising=False)
    assert "nobugs-soc-graylog-1" in setup.status_report(False)["containers"]
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "nobugs-clean")
    assert "nobugs-clean-graylog-1" in setup.status_report(False)["containers"]
