import uuid
from contextvars import ContextVar
from typing import Callable

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Send

from app.core.logging import request_id_var


class RequestIDMiddleware:
    """ASGI middleware that generates and propagates request_id.

    Behavior:
    - Generate new UUID for each request
    - Accept X-Request-ID from client if present (for tracing)
    - Set request_id in ContextVar for logging
    - Add X-Request-ID to response headers
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope, receive: Receive, send: Send) -> None:
        # Get request_id from headers or generate new one
        headers = Headers(scope=scope)
        request_id = headers.get("x-request-id", uuid.uuid4().hex)

        # Set in context variable
        token = request_id_var.set(request_id)

        # Track status code for logging
        status_code = 200

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                # Add request_id to response headers
                message["headers"].append((b"x-request-id", request_id.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            request_id_var.reset(token)
