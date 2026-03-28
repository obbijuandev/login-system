from fastapi import FastAPI

from app.api.v1 import auth, user
from app.core.config import config
from app.core.exception_handlers import register_exception_handlers
from app.core.logging import setup_logging
from app.db.schema import init_db

setup_logging()
init_db()

app = FastAPI(title=config.app_name)
register_exception_handlers(app)

# Registrar rutas
app.include_router(user.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")
