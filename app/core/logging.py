import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

# Variable de contexto para request ID - seguro para async
request_id_var: ContextVar[str] = ContextVar("request_id", default="")


class JSONFormatter(logging.Formatter):
    """Formateador de logs JSON estructurado con request_id de contexto."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Agregar request_id si está definido
        req_id = request_id_var.get()
        if req_id:
            log_obj["request_id"] = req_id

        # Agregar campos extra del registro
        if hasattr(record, "user_id"):
            log_obj["user_id"] = record.user_id
        if hasattr(record, "action"):
            log_obj["action"] = record.action

        # Agregar info de excepción si existe
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def setup_logging():
    """Configura logging estructurado en JSON."""
    # Configurar root logger con formateador JSON
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(logging.INFO)

    # También configurar basic logging para casos donde se use basicConfig
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",  # El formateador JSON maneja el formato
    )
