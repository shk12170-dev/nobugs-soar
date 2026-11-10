"""S7 기준본 모듈: 스냅샷·상태 조회·복구·격리(순수 파일 연산, 서버 없이 시험)."""
import pytest

from nobugs_portal import baseline


@pytest.fixture
def web(tmp_path):
    root = tmp_path / "web"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text("<html>home</html>", encoding="utf-8")
    (root / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    return root


@pytest.fixture
def base(tmp_path):
    return tmp_path / "baseline"


@pytest.fixture
def quarantine(tmp_path):
    return tmp_path / "quarantine"


def test_snapshot_copies_every_file_and_keys_are_relative_posix_paths(web, base):
    copied = baseline.snapshot(web, base)
    assert set(copied) == {"index.html", "assets/app.js"}
    assert (base / "index.html").read_text(encoding="utf-8") == "<html>home</html>"
    assert baseline.baseline_keys(base) == {"index.html", "assets/app.js"}


def test_snapshot_overwrites_an_existing_baseline(web, base):
    baseline.snapshot(web, base)
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    baseline.snapshot(web, base)
    assert baseline.baseline_hash(base, "index.html") == baseline.current_hash(web, "index.html")


def test_file_state_reports_matching_and_tampered_and_unknown_files(web, base):
    baseline.snapshot(web, base)
    assert baseline.file_state(web, base, "index.html")["matches_baseline"] is True
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    tampered = baseline.file_state(web, base, "index.html")
    assert tampered["matches_baseline"] is False and tampered["known_to_baseline"] is True
    (web / "unexpected.txt").write_text("not-a-real-file: just a stand-in for an unexpected upload", encoding="utf-8")
    unknown = baseline.file_state(web, base, "unexpected.txt")
    assert unknown["known_to_baseline"] is False and unknown["matches_baseline"] is False


def test_file_state_for_a_deleted_file_has_no_current_hash(web, base):
    baseline.snapshot(web, base)
    (web / "index.html").unlink()
    state = baseline.file_state(web, base, "index.html")
    assert state["current_hash"] is None and state["known_to_baseline"] is True and not state["matches_baseline"]


def test_restore_overwrites_the_tampered_file_with_the_baseline_copy(web, base):
    baseline.snapshot(web, base)
    (web / "index.html").write_text("<html>defaced</html>", encoding="utf-8")
    result = baseline.restore(web, base, "index.html")
    assert result == {"file_key": "index.html", "changed": True, "restored": True, "hash": result["hash"]}
    assert (web / "index.html").read_text(encoding="utf-8") == "<html>home</html>"


def test_restore_is_idempotent_when_already_matching(web, base):
    baseline.snapshot(web, base)
    first = baseline.restore(web, base, "index.html")
    assert first["changed"] is False and first["restored"] is True


def test_restore_also_recreates_a_deleted_file(web, base):
    baseline.snapshot(web, base)
    (web / "index.html").unlink()
    result = baseline.restore(web, base, "index.html")
    assert result["restored"] is True and (web / "index.html").is_file()


def test_restore_refuses_a_file_key_that_is_not_in_the_baseline(web, base):
    with pytest.raises(baseline.BaselineError, match="격리 대상"):
        baseline.restore(web, base, "unexpected.txt")


def test_restore_and_file_state_refuse_path_escape(web, base):
    baseline.snapshot(web, base)
    with pytest.raises(baseline.BaselineError):
        baseline.restore(web, base, "../secret.txt")
    assert baseline.current_hash(web, "../../etc/passwd") is None


def test_quarantine_moves_an_unbaselined_file_out_of_the_web_root(web, base, quarantine):
    baseline.snapshot(web, base)
    (web / "unexpected.txt").write_text("not-a-real-file: just a stand-in for an unexpected upload", encoding="utf-8")
    result = baseline.quarantine(web, quarantine, "unexpected.txt")
    assert result["changed"] is True and result["quarantined"] is True
    assert not (web / "unexpected.txt").exists()
    assert "unexpected.txt" in result["quarantine_path"]


def test_quarantine_on_an_already_missing_file_is_a_no_op(web, quarantine):
    result = baseline.quarantine(web, quarantine, "already-gone.txt")
    assert result == {"file_key": "already-gone.txt", "changed": False, "quarantined": False}


def test_quarantine_refuses_path_escape(web, quarantine):
    with pytest.raises(baseline.BaselineError):
        baseline.quarantine(web, quarantine, "../outside.txt")
