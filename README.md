# LoginSystem

API construida con FastAPI para autenticación, gestión de usuarios y autorización por roles.

## Stack actual

- Python 3.13
- FastAPI
- SQLAlchemy ORM
- SQLite
- Pydantic Settings
- Uvicorn / Gunicorn
- `uv` para dependencias

## Estado funcional actual

El proyecto incluye:

- autenticación con JWT
- registro de usuarios
- login
- endpoint `/auth/me`
- roles persistidos en base de datos
- autorización por rol sobre endpoints de usuarios
- bootstrap controlado del primer `ADMIN`

## Roles disponibles

Los roles iniciales del sistema son:

- `ADMIN`
- `AGENTE`
- `SUPERVISOR`

### Regla de registro

Todo usuario que se registra desde `/api/v1/auth/register` queda con rol:

- `AGENTE`

## Reglas de autorización actuales

### ADMIN

- puede listar usuarios
- puede ver cualquier usuario
- puede editar cualquier usuario
- puede eliminar cualquier usuario

### SUPERVISOR

- puede listar usuarios
- puede ver cualquier usuario
- puede editar cualquier usuario
- no puede eliminar usuarios

### AGENTE

- no puede listar todos los usuarios
- puede ver solo su propio usuario
- puede editar solo su propio usuario
- no puede eliminar usuarios

## Estructura general

- `app/api/v1/` → endpoints HTTP
- `app/api/dependencies.py` → dependencias de autenticación y autorización
- `app/services/` → lógica de negocio
- `app/db/schema.py` → modelos ORM, inicialización y migración básica SQLite
- `app/core/security.py` → hashing, JWT y validaciones de seguridad
- `app/commands/` → comandos operativos por CLI

## Ejecución local

### Instalar dependencias

```bash
uv sync
```

### Levantar la aplicación

```bash
uv run uvicorn app.main:app --reload
```

La aplicación quedará disponible por defecto en:

```text
http://localhost:8000
```

## Variables y configuración

La configuración principal vive en `app/core/config.py`.

Valores relevantes:

- nombre de la app: `LoginSystem`
- base de datos SQLite
- secreto JWT
- algoritmo JWT
- expiración del access token

## Flujo básico de autenticación

### 1. Registrar usuario

```bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "password": "super-secret"
  }'
```

### 2. Hacer login

```bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "ada@example.com",
    "password": "super-secret"
  }'
```

### 3. Consultar usuario autenticado

```bash
curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer <access-token>"
```

## Endpoints principales

### Autenticación

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`

### Usuarios

- `GET /api/v1/users`
- `GET /api/v1/users/{user_id}`
- `PUT /api/v1/users/{user_id}`
- `DELETE /api/v1/users/{user_id}`

> `POST /api/v1/users` fue deshabilitado. El alta de usuarios vive en `/api/v1/auth/register`.

## Bootstrap del primer ADMIN

El sistema NO crea administradores automáticamente.

Para promover al primer `ADMIN`, primero debe existir un usuario registrado y luego ejecutar el comando:

```bash
uv run python -m app.commands.bootstrap_first_admin --email correo@ejemplo.com
```

### Reglas del bootstrap

- solo promueve usuarios existentes
- falla si ya existe al menos un `ADMIN`
- no expone endpoint HTTP
- no crea usuarios nuevos

## Base de datos y migración actual

El proyecto usa SQLite y una estrategia de migración básica en código para compatibilidad legacy.

Actualmente el sistema:

- crea tablas faltantes
- agrega columnas nuevas necesarias en SQLite legacy
- siembra roles iniciales
- hace backfill de usuarios antiguos cuando corresponde

> Esta estrategia es suficiente para el estado actual del proyecto, pero NO reemplaza un sistema formal de migraciones si la aplicación sigue creciendo.

## Ejecutar tests

### Suite de tests

```bash
uv run pytest
```

### Tests puntuales

```bash
uv run pytest tests/api/v1/test_auth.py
uv run pytest tests/api/v1/test_user.py
uv run pytest tests/test_db.py
```

## Docker

### Levantar con Docker Compose

```bash
docker compose up -d --build
```

### Reiniciar desde cero

```bash
docker compose down --volumes --remove-orphans
docker compose build --no-cache
docker compose up -d
```

## Mantenimiento de dependencias

Si actualizas dependencias:

```bash
uv lock --upgrade
uv sync
```

## Notas importantes

- los mensajes de la API están en español
- los errores del framework más comunes también fueron adaptados al español
- el rol NO se guarda dentro del JWT; se resuelve desde base de datos
- el primer `ADMIN` se obtiene por bootstrap controlado, no por registro público
