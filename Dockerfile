FROM python:3.13.11-slim-bookworm

# Dependencias del sistema necesarias para wheels nativos y para uv
RUN apt-get update && apt-get install --no-install-recommends -y \
    build-essential \
    wget \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instalar uv
ADD https://astral.sh/uv/install.sh /install.sh
RUN chmod +x /install.sh && /install.sh && rm /install.sh

# Hacemos que uv esté disponible para todos los usuarios
ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

# Copiamos SOLO los archivos de dependencias primero
# Esto permite que Docker use cache si no cambian las dependencias
COPY pyproject.toml uv.lock ./

# Instalar dependencias exactamente desde uv.lock
RUN uv sync --frozen

# Creamos un usuario no root para ejecutar la app (seguridad)
RUN useradd -m appuser && chown -R appuser:appuser /app

# Copiamos ahora el resto de la aplicación
COPY --chown=appuser:appuser . .

# Cambiamos al usuario no root
USER appuser

EXPOSE 80

# Gunicorn actúa como process manager:
# si un worker de Uvicorn se cae o se cuelga, Gunicorn lo reemplaza automáticamente
CMD ["uv", "run", "gunicorn", "app.main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:80"]
