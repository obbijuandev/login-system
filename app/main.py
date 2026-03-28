from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

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

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
register_exception_handlers(app)


@app.get("/health")
def health_check():
    return {"status": "healthy"}


# Registrar rutas
app.include_router(user.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
