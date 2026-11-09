"""시작 시 DB 준비: 두 앱이 동시에 시작해도 표 생성이 경쟁으로 실패하지 않는다."""
import pytest
from sqlalchemy.exc import OperationalError

from nobugs_portal import db as db_module
from nobugs_portal.db import Database


def test_create_all_retries_when_another_process_created_the_tables(tmp_path, monkeypatch):
    calls = {"n": 0}
    real = db_module.Base.metadata.create_all

    def flaky(engine):
        calls["n"] += 1
        if calls["n"] < 3:
            raise OperationalError("CREATE TABLE users", {}, Exception("table users already exists"))
        real(engine)

    monkeypatch.setattr(db_module.Base.metadata, "create_all", flaky)
    database = Database(f"sqlite:///{(tmp_path / 'race.db').as_posix()}")
    database.create_all()
    assert calls["n"] == 3
    database.dispose()


def test_create_all_does_not_hide_other_errors(tmp_path, monkeypatch):
    def broken(engine):
        raise OperationalError("SELECT 1", {}, Exception("disk I/O error"))

    monkeypatch.setattr(db_module.Base.metadata, "create_all", broken)
    database = Database(f"sqlite:///{(tmp_path / 'x.db').as_posix()}")
    with pytest.raises(OperationalError):
        database.create_all()
    database.dispose()


def test_two_databases_on_one_file_can_both_prepare_it(tmp_path):
    url = f"sqlite:///{(tmp_path / 'shared.db').as_posix()}"
    first, second = Database(url), Database(url)
    first.create_all()
    second.create_all()  # 이미 있어도 오류 없이 끝난다
    first.dispose()
    second.dispose()
