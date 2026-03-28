from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

from sqlalchemy.orm import Session, sessionmaker

from app.db.schema import SessionLocal, init_db
from app.services.admin_bootstrap_service import (
    AdminBootstrapError,
    AdminBootstrapService,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Promueve por única vez a un usuario existente como ADMIN."
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Correo electrónico del usuario existente que se promoverá a ADMIN",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    session_factory: sessionmaker[Session] | Callable[[], Session] = SessionLocal,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    init_db_fn: Callable[[], None] = init_db,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output = stdout or sys.stdout
    error_output = stderr or sys.stderr

    init_db_fn()

    session = session_factory()
    try:
        service = AdminBootstrapService(session=session)
        user = service.promote_first_admin_by_email(args.email)
    except AdminBootstrapError as exc:
        print(f"Error: {exc}", file=error_output)
        return 1
    finally:
        session.close()

    print(f"Usuario '{user.email}' promovido correctamente a ADMIN.", file=output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
