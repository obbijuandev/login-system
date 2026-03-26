
FastAPI 0.128.0
Python 3.13.11
Pydantic 2.12
SQLModel 0.0.32
SQLAlchemy 2.0.46
gunicorn 25.0.0
uvicorn 0.40.0


Docker Compose:

Para levantar el proyecto:
docker compose build --no-cache
docker compose up -d

Para borrar y levantar el proyecto:
docker compose down --volumes --remove-orphans
docker compose build --no-cache
docker compose up -d

Si solo cambias código:
docker compose up -d --build

Si cambias dependencias:
docker compose down
docker compose build --no-cache
docker compose up -d


¿Qué pasa si quieres actualizar el proyecto?

El flujo correcto es:

uv lock --upgrade
uv sync

Esto:
- recalcula versiones
- respeta Python 3.13
- vuelve a generar uv.lock
- Si algo no es compatible, uv no lo resolverá.

Regla para tu proyecto

Si usas SQLModel:
- Nunca actualices Pydantic o SQLAlchemy sin regenerar uv.lock.

Siempre:
uv lock --upgrade
uv sync


Example requests:

Here’s a set of simple curl examples you can use to interact with your FastAPI app once it’s running (default at http://localhost:8000):

1️⃣ Create a User

curl -X POST "http://localhost:8000/api/v1/users" \
     -H "Content-Type: application/json" \
     -d '{"name": "Ada Lovelace"}'


2️⃣ Get All Users

curl -X GET "http://localhost:8000/api/v1/users"


3️⃣ Get a User by ID

(Replace 1 with the actual ID from the create response)

curl -X GET "http://localhost:8000/api/v1/users/1"


4️⃣ Update a User

curl -X PUT "http://localhost:8000/api/v1/users/1" \
     -H "Content-Type: application/json" \
     -d '{"name": "Grace Hopper"}'


⸻

5️⃣ Delete a User

curl -X DELETE "http://localhost:8000/api/v1/users/1"





