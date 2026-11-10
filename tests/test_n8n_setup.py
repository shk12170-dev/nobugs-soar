"""n8n 반입 도구의 시험. 실제 docker는 부르지 않고 자격 증명 구성·명령·순서만 확인한다."""
import json
import subprocess

import pytest

from nobugs_tools import n8n_setup


def test_build_credentials_covers_what_the_workflow_references():
    creds = n8n_setup.build_credentials({"NB_N8N_WEBHOOK_KEY": "wk", "NB_ENGINE_KEY": "ek"})
    by_name = {c["name"]: c for c in creds}
    assert set(by_name) == {"S1 Webhook Key", "Engine Key"}
    assert by_name["S1 Webhook Key"]["data"] == {"name": "X-N8N-Webhook-Key", "value": "wk"}
    assert by_name["Engine Key"]["data"] == {"name": "X-Engine-Key", "value": "ek"}
    assert all(c["type"] == "httpHeaderAuth" for c in creds)


def test_build_credentials_names_the_missing_key(monkeypatch):
    with pytest.raises(n8n_setup.N8nSetupError, match="NB_ENGINE_KEY"):
        n8n_setup.build_credentials({"NB_N8N_WEBHOOK_KEY": "wk"})


def test_workflow_json_in_the_repo_has_a_top_level_id():
    """최상위 id가 없으면 import:workflow가 SQLite NOT NULL로 실패한다(실제로 겪은 문제)."""
    for path in sorted(n8n_setup.WORKFLOW_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data.get("id"), f"{path.name}에 최상위 id가 없다"
        assert data.get("nodes") and data.get("connections")


def test_workflow_json_carries_no_secret_values():
    """키는 n8n 자격 증명으로 넘긴다 - 워크플로 JSON에는 값이 들어가면 안 된다(커밋되는 파일)."""
    for path in sorted(n8n_setup.WORKFLOW_DIR.glob("*.json")):
        raw = path.read_text(encoding="utf-8")
        assert "$env." not in raw          # 표현식 $env 접근은 기본 차단이라 쓰면 런타임에 깨진다
        for node in json.loads(raw)["nodes"]:
            for cred in (node.get("credentials") or {}).values():
                assert set(cred) <= {"id", "name"}      # 값이 아니라 참조만


def test_import_credentials_writes_the_file_and_copies_it(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(n8n_setup, "CREDENTIALS_FILE", tmp_path / "credentials.local.json")
    monkeypatch.setattr(n8n_setup, "run", lambda cmd: calls.append(cmd) or
                       subprocess.CompletedProcess(cmd, 0))
    n8n_setup.import_credentials({"NB_N8N_WEBHOOK_KEY": "wk", "NB_ENGINE_KEY": "ek"})
    written = json.loads((tmp_path / "credentials.local.json").read_text(encoding="utf-8"))
    assert {c["name"] for c in written} == {"S1 Webhook Key", "Engine Key"}
    assert any(c[0] == "docker" and c[1] == "cp" for c in calls)
    assert any("import:credentials" in " ".join(c) for c in calls)


def test_publish_and_restart_publishes_every_workflow_then_restarts(monkeypatch):
    calls = []
    monkeypatch.setattr(n8n_setup, "run", lambda cmd: calls.append(" ".join(cmd)) or
                       subprocess.CompletedProcess(cmd, 0))
    n8n_setup.publish_and_restart()
    published = [c for c in calls if "publish:workflow" in c]
    assert len(published) == len(n8n_setup.WORKFLOW_IDS)
    assert "restart n8n" in calls[-1]      # 재시작이 마지막이어야 활성화가 적용된다


def test_import_credentials_fails_loudly_when_docker_cp_fails(monkeypatch, tmp_path):
    monkeypatch.setattr(n8n_setup, "CREDENTIALS_FILE", tmp_path / "credentials.local.json")
    monkeypatch.setattr(n8n_setup, "run", lambda cmd: subprocess.CompletedProcess(cmd, 1))
    with pytest.raises(n8n_setup.N8nSetupError):
        n8n_setup.import_credentials({"NB_N8N_WEBHOOK_KEY": "wk", "NB_ENGINE_KEY": "ek"})
