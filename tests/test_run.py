"""서버 실행기(nobugs_tools.run) 시험: .env 반영·우선순위·실행 명령."""
from __future__ import annotations

from nobugs_tools import run


def test_env_file_values_are_read_and_comments_skipped(tmp_path):
    f = tmp_path / ".env"
    f.write_text("# 주석\nNB_ENGINE_KEY=ek\n\n  NB_GELF_PORT = 12301 \n", encoding="utf-8")
    assert run.read_env_file(f) == {"NB_ENGINE_KEY": "ek", "NB_GELF_PORT": "12301"}
    assert run.read_env_file(tmp_path / "없음") == {}


def test_terminal_beats_env_file_beats_local_defaults():
    env = run.build_env({"NB_ENGINE_RELEASE_TTL": "30"},
                        {"NB_ENGINE_RELEASE_TTL": "90", "NB_ENGINE_KEY": "ek", "NB_GELF_ENABLED": "false"})
    assert env["NB_ENGINE_RELEASE_TTL"] == "30"          # 터미널에서 잠깐 바꾼 값이 이긴다
    assert env["NB_ENGINE_KEY"] == "ek"                  # .env 값이 들어간다(빈 키로 401이 나던 실수 방지)
    assert env["NB_GELF_ENABLED"] == "false"             # .env가 로컬 기본값을 이긴다
    assert env["NB_RESPONSE_ALLOWED_CIDRS"] == "127.0.0.0/8"
    assert env["PYTHONPATH"].endswith("src")


def test_main_launches_the_target_with_the_env(tmp_path, monkeypatch, capsys):
    f = tmp_path / ".env"
    f.write_text("NB_ENGINE_KEY=secret-value\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(run.subprocess, "call", lambda cmd, env, cwd: calls.append((cmd, env)) or 0)
    assert run.main(["engine", "--env-file", str(f)]) == 0
    cmd, env = calls[0]
    assert cmd[1:] == ["-m", "nobugs_engine"] and env["NB_ENGINE_KEY"] == "secret-value"
    out = capsys.readouterr().out
    assert "secret-value" not in out   # 비밀값은 화면에 찍지 않는다
    out.encode("cp949")                # 한국어 Windows 콘솔(cp949)에서 출력하다 죽지 않는다(실제로 겪은 문제)
    assert run.main(["portal", "--env-file", str(f)]) == 0
    assert "nobugs_portal.app:public_factory" in calls[1][0] and "5100" in calls[1][0]


def test_missing_env_file_is_a_clear_error(tmp_path, capsys):
    assert run.main(["portal", "--env-file", str(tmp_path / ".env")]) == 2
    assert "make_env" in capsys.readouterr().err
