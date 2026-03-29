"""Store de rate limiting basado en SQLite para uso multi-worker."""

import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Column, DateTime, Index, Integer, String, create_engine, text
from sqlalchemy.orm import Session, sessionmaker, declarative_base

Base = declarative_base()


class RateLimitEntry(Base):
    """Tabla para tracking de rate limiting por IP y endpoint."""

    __tablename__ = "rate_limits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False)  # IPv6 max length
    endpoint = Column(String(255), nullable=False)
    counter = Column(Integer, default=0)
    window_start = Column(DateTime, nullable=False)
    last_updated = Column(DateTime, nullable=False)

    __table_args__ = (Index("ix_rate_limits_ip_endpoint", "ip_address", "endpoint"),)


class RateLimitStore:
    """Store de rate limiting con limpieza automática de entradas expiradas."""

    def __init__(self, db_path: str = "./ratelimit.db"):
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

    def is_rate_limited(
        self, ip_address: str, endpoint: str, limit: int, window_seconds: int
    ) -> bool:
        """Verifica si la IP está rate-limited para el endpoint dado."""
        now = time.time()
        window_start = datetime.fromtimestamp(now - window_seconds, tz=timezone.utc)
        last_updated = datetime.fromtimestamp(now, tz=timezone.utc)

        with self.get_session() as session:
            # Limpiar entradas expiradas
            session.execute(
                text("DELETE FROM rate_limits WHERE last_updated < :window_start"),
                {"window_start": window_start},
            )

            # Buscar entrada actual
            entry = (
                session.query(RateLimitEntry)
                .filter(
                    RateLimitEntry.ip_address == ip_address,
                    RateLimitEntry.endpoint == endpoint,
                )
                .first()
            )

            if entry is None:
                # Primera request en la ventana
                new_entry = RateLimitEntry(
                    ip_address=ip_address,
                    endpoint=endpoint,
                    counter=1,
                    window_start=last_updated,
                    last_updated=last_updated,
                )
                session.add(new_entry)
                session.commit()
                return False

            if entry.counter >= limit:
                return True

            # Incrementar contador
            entry.counter += 1
            entry.last_updated = last_updated
            session.commit()
            return False

    def clear(self) -> None:
        """Limpia todas las entradas de rate limiting."""
        with self.get_session() as session:
            session.execute(text("DELETE FROM rate_limits"))
            session.commit()


# Instancia global
rate_limit_store = RateLimitStore()
