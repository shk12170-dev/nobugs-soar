"""S7 기준본: 웹 루트의 "정상 상태"를 저장해 두고, 변조를 복구하거나 낯선 파일을 격리한다.

기준본은 배포 시점에 한 번 `snapshot()`으로 떠서 `instance/baseline/`(Git 제외)에 그대로 복사해 둔다.
복구는 기준본 파일을 웹 루트에 덮어쓰는 것이고, 격리는 기준본에 없는 파일을 웹 루트 밖(`instance/quarantine/`)으로
옮기는 것이다. 둘 다 파일 키(웹 루트 기준 상대 경로)로 가리킨다.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import shutil
from pathlib import Path


class BaselineError(Exception):
    """파일 키가 기준본 바깥(경로 탈출)을 가리키거나 존재하지 않을 때."""


def _safe_path(root: Path, file_key: str) -> Path:
    try:
        target = (root / file_key).resolve()
    except (OSError, ValueError) as exc:
        raise BaselineError(f"올바르지 않은 경로: {file_key}") from exc
    if not target.is_relative_to(root.resolve()):
        raise BaselineError(f"웹 루트 바깥을 가리키는 경로: {file_key}")
    return target


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(web_root: str | Path, baseline_dir: str | Path) -> list[str]:
    """지금 웹 루트의 모든 파일을 기준본으로 그대로 복사한다(기존 기준본은 덮어쓴다). 복사한 파일 키 목록을 돌려준다."""
    root, base = Path(web_root).resolve(), Path(baseline_dir).resolve()
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True, exist_ok=True)
    copied = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            key = path.relative_to(root).as_posix()
            dest = base / key
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            copied.append(key)
    return copied


def baseline_keys(baseline_dir: str | Path) -> set[str]:
    base = Path(baseline_dir)
    if not base.exists():
        return set()
    return {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()}


def baseline_hash(baseline_dir: str | Path, file_key: str) -> str | None:
    """기준본에 그 파일 키가 있으면 해시를, 없으면 None을 돌려준다."""
    base = Path(baseline_dir).resolve()
    if not base.exists():
        return None
    try:
        target = _safe_path(base, file_key)
    except BaselineError:
        return None
    return _hash_file(target) if target.is_file() else None


def current_hash(web_root: str | Path, file_key: str) -> str | None:
    """지금 웹 루트에 그 파일이 있으면 해시를, 없으면(지워졌으면) None을 돌려준다."""
    root = Path(web_root).resolve()
    try:
        target = _safe_path(root, file_key)
    except BaselineError:
        return None
    return _hash_file(target) if target.is_file() else None


def file_state(web_root: str | Path, baseline_dir: str | Path, file_key: str) -> dict:
    """파일 키 하나의 상태: 지금 해시, 기준본 해시, 기준본과 같은지, 기준본에 있는 파일인지."""
    current, baseline = current_hash(web_root, file_key), baseline_hash(baseline_dir, file_key)
    return {"file_key": file_key, "current_hash": current, "baseline_hash": baseline,
            "matches_baseline": current is not None and current == baseline, "known_to_baseline": baseline is not None}


def restore(web_root: str | Path, baseline_dir: str | Path, file_key: str) -> dict:
    """기준본 파일을 웹 루트에 덮어쓴다. 기준본에 없는 파일 키면 BaselineError(그런 경우는 격리 대상)."""
    base_hash = baseline_hash(baseline_dir, file_key)
    if base_hash is None:
        raise BaselineError(f"기준본에 없는 파일은 복구가 아니라 격리 대상: {file_key}")
    root, base = Path(web_root).resolve(), Path(baseline_dir).resolve()
    before = current_hash(web_root, file_key)
    src, dest = _safe_path(base, file_key), _safe_path(root, file_key)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    after = _hash_file(dest)
    return {"file_key": file_key, "changed": before != after, "restored": after == base_hash, "hash": after}


def quarantine(web_root: str | Path, quarantine_dir: str | Path, file_key: str) -> dict:
    """웹 루트에서 그 파일을 치워 격리 폴더로 옮긴다(같은 이름이 있으면 시각을 붙인다). 원래 없었으면 변화 없음."""
    root, qdir = Path(web_root).resolve(), Path(quarantine_dir).resolve()
    src = _safe_path(root, file_key)
    if not src.is_file():
        return {"file_key": file_key, "changed": False, "quarantined": False}
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%f")
    dest = qdir / f"{stamp}__{file_key.replace('/', '__')}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    return {"file_key": file_key, "changed": True, "quarantined": True, "quarantine_path": str(dest)}
