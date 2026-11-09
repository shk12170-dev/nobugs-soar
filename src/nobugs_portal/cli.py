"""계정 관리 명령. 예: python -m nobugs_portal.cli create-user --username staff1 --role staff

비밀번호는 명령줄 인자로 받지 않는다(셸 기록에 남기 때문). 환경변수(--password-env)나 숨김 입력을 쓴다.
"""
from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import sys

from sqlalchemy import func, select

from .config import Settings
from .db import Database
from .models import User
from .security import hash_password
from .services import find_user

ROLES = ("citizen", "staff", "admin")
USERNAME = re.compile(r"^[A-Za-z0-9_]{3,40}$")


def create_user(db: Database, username: str, display_name: str, role: str, password: str) -> User:
    if not USERNAME.match(username):
        raise ValueError("아이디는 영문·숫자·밑줄 3~40자여야 합니다.")
    if role not in ROLES:
        raise ValueError(f"역할은 {', '.join(ROLES)} 중 하나여야 합니다.")
    if not 2 <= len(display_name) <= 30:
        raise ValueError("표시 이름은 2~30자여야 합니다.")
    if not 10 <= len(password) <= 128:
        raise ValueError("비밀번호는 10~128자여야 합니다.")
    with db.session() as session:
        if find_user(session, username) is not None:
            raise ValueError("이미 존재하는 아이디입니다.")
        user = User(username=username.lower(), display_name=display_name,
                    password_hash=hash_password(password), role=role)
        session.add(user)
        session.commit()
        return user


def seed_demo(db: Database) -> dict[str, str]:
    """빈 DB에만 시연 계정 3개를 만들고 무작위 비밀번호를 돌려준다(한 번만 표시)."""
    with db.session() as session:
        if (session.scalar(select(func.count()).select_from(User)) or 0) > 0:
            raise ValueError("빈 DB에서만 실행합니다. 기존 계정을 건드리지 않습니다.")
    created = {}
    for username, name, role in (("citizen_demo", "시연 시민", "citizen"), ("staff_demo", "시연 담당자", "staff"),
                                 ("admin_demo", "시연 관리자", "admin")):
        password = secrets.token_urlsafe(14)
        create_user(db, username, name, role, password)
        created[username] = password
    return created


def main(argv: list[str] | None = None, settings: Settings | None = None) -> int:
    parser = argparse.ArgumentParser(prog="nobugs_portal.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("create-user")
    make.add_argument("--username", required=True)
    make.add_argument("--display-name", default=None)
    make.add_argument("--role", choices=ROLES, default="citizen")
    make.add_argument("--password-env", help="비밀번호가 든 환경변수 이름(없으면 숨김 입력)")
    sub.add_parser("seed-demo")
    args = parser.parse_args(argv)

    db = Database((settings or Settings.from_env()).database_url)
    db.create_all()
    try:
        if args.command == "create-user":
            password = os.environ.get(args.password_env, "") if args.password_env else getpass.getpass("비밀번호: ")
            create_user(db, args.username, args.display_name or args.username, args.role, password)
            print(f"계정을 만들었습니다: {args.username} ({args.role})")
        else:
            for username, password in seed_demo(db).items():
                print(f"{username}  {password}")
            print("위 비밀번호는 지금만 표시됩니다.")
    except ValueError as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1
    finally:
        db.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
