"""Middlewares de rate limiting usando SQLite store."""

import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from app.services.rate_limit_store import rate_limit_store


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware de rate limiting por IP y endpoint."""

    # Rate limits: (endpoint_prefix, limit, window_seconds)
    LIMITS = {
        "/api/v1/auth/login": (5, 60),  # 5 por minuto
        "/api/v1/auth/register": (3, 60),  # 3 por minuto
        "/api/v1/auth/resend-verification": (3, 60),  # 3 por minuto
        "/api/v1/auth/refresh": (10, 60),  # 10 por minuto
    }

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Omitir rate limiting en modo test
        if os.getenv("TESTING", "").lower() == "true":
            return await call_next(request)

        # Solo aplicar rate limiting a endpoints específicos
        for prefix, (limit, window) in self.LIMITS.items():
            if path.startswith(prefix):
                client_ip = self._get_client_ip(request)

                if rate_limit_store.is_rate_limited(client_ip, path, limit, window):
                    return JSONResponse(
                        status_code=429,
                        content={
                            "detail": "Demasiadas solicitudes. Intenta más tarde."
                        },
                    )
                break

        return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
