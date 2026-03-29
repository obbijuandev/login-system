"""Token blocklist service usando SQLite para invalidación server-side."""

import time
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, create_engine, text
from sqlalchemy.orm import Session, sessionmaker, declarative_base

Base = declarative_base()


class BlockedToken(Base):
    """Tabla para almacenar tokens bloqueados."""

    __tablename__ = "blocked_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    blocked_at = Column(DateTime, nullable=False)


class SQLiteTokenBlocklist:
    """Blocklist de tokens persistido en SQLite."""

    def __init__(self, db_path: str = "./tokenblocklist.db"):
        db_url = f"sqlite:///{db_path}"
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

    @contextmanager
    def get_session(self):
        session = self.SessionLocal()
        try:
            yield session
        finally:
            session.close()

    def add(self, jti: str) -> None:
        """Bloquea un token por su JTI."""
        with self.get_session() as session:
            blocked = BlockedToken(jti=jti, blocked_at=datetime.now(timezone.utc))
            session.merge(blocked)  # Usar merge para manejar duplicados
            session.commit()

    def is_blocked(self, jti: str) -> bool:
        """Verifica si un token está bloqueado."""
        with self.get_session() as session:
            return (
                session.query(BlockedToken).filter(BlockedToken.jti == jti).first()
                is not None
            )

    def remove(self, jti: str) -> None:
        """Desbloquea un token."""
        with self.get_session() as session:
            session.query(BlockedToken).filter(BlockedToken.jti == jti).delete()
            session.commit()

    def clear(self) -> None:
        """Limpia todos los tokens bloqueados."""
        with self.get_session() as session:
            session.execute(text("DELETE FROM blocked_tokens"))
            session.commit()


# Instancia global
token_blocklist = SQLiteTokenBlocklist()
