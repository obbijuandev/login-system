from fastapi import FastAPI

from app.api.middlewares import RateLimitMiddleware
from app.api.v1 import auth, user
from app.core.config import config
from app.core.exception_handlers import register_exception_handlers
from app.core.limiter import limiter
from app.core.logging import setup_logging
from app.core.logging_middleware import RequestIDMiddleware
from app.db.schema import init_db

setup_logging()
init_db()

app = FastAPI(title=config.app_name)

# Add request ID middleware FIRST (outermost)
app.add_middleware(RequestIDMiddleware)

# Add rate limiting middleware using SQLite (shared across workers)
app.add_middleware(RateLimitMiddleware)

app.state.limiter = limiter
register_exception_handlers(app)


# Registrar rutas
app.include_router(user.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
