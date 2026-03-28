import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

# Context variable for request ID - thread/async safe
request_id_var: ContextVar[str] = ContextVar("request_id", default="")


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter with request_id context."""

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

        # Add request_id if set
        req_id = request_id_var.get()
        if req_id:
            log_obj["request_id"] = req_id

        # Add extra fields from record
        if hasattr(record, "user_id"):
            log_obj["user_id"] = record.user_id
        if hasattr(record, "action"):
            log_obj["action"] = record.action

        # Add exception info if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def setup_logging():
    """Configure structured JSON logging."""
    # Configure root logger with JSON formatter
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(logging.INFO)

    # Also configure basic logging for cases where basicConfig is used
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",  # JSON formatter handles formatting
    )
