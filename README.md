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

## Arquitectura

```
app/
├── api/
│   ├── v1/
│   │   ├── auth.py           # Endpoints: login, register, refresh, logout, me
│   │   └── user.py           # Endpoints: CRUD usuarios + gestión de roles
│   └── dependencies.py        # Auth dependencies (get_current_user, require_role)
├── core/
│   ├── config.py              # Configuración JWT (30 min access, 7 day refresh)
│   └── security.py            # JWT creation/validation + password hashing (PBKDF2)
├── models/
│   ├── auth.py                # Token, RefreshRequest, LogoutRequest, LoginRequest
│   └── user.py                # UserRead, UserCreate, RoleRead, etc.
├── services/
│   ├── auth_service.py        # Login, register, refresh_access_token, logout
│   └── user_service.py        # User CRUD + role management
├── db/
│   └── schema.py              # SQLAlchemy models (User, Role)
└── commands/
    └── bootstrap_first_admin.py  # CLI para promover primer ADMIN

tests/                          # 49 tests cubriendo toda la funcionalidad
```

### Patrón de arquitectura: Service Layer

```
HTTP Request → API Endpoint → Service Layer → DB (SQLAlchemy)
                ↓
         Dependencies (auth, authorization)
```

### JWT Flow

```
Login → access_token (30 min) + refresh_token (7 days, rotation)
    ↓
 使用access_token进行API调用
    ↓
 Token过期 → POST /auth/refresh → 新tokens
    ↓
 Logout → POST /auth/logout → refresh token invalidated
```

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

> Retorna: `{ "access_token": "...", "refresh_token": "...", "token_type": "bearer" }`

### 3. Consultar usuario autenticado

```bash
curl -X GET "http://localhost:8000/api/v1/auth/me" \
  -H "Authorization: Bearer <access-token>"
```

### 4. Refrescar tokens (cuando access_token expira)

```bash
curl -X POST "http://localhost:8000/api/v1/auth/refresh" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>"
  }'
```

> El refresh token anterior es invalidado (rotación) y se emiten nuevos tokens.

### 5. Logout

```bash
curl -X POST "http://localhost:8000/api/v1/auth/logout" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>"
  }'
```

## Endpoints principales

### Autenticación

- `POST /api/v1/auth/register` — Registrar usuario (rol AGENTE por defecto)
- `POST /api/v1/auth/login` — Login (retorna access + refresh token)
- `GET /api/v1/auth/me` — Usuario autenticado
- `POST /api/v1/auth/refresh` — Refrescar tokens (rotation)
- `POST /api/v1/auth/logout` — Invalidar refresh token

### Usuarios

- `GET /api/v1/users` — Listar usuarios (ADMIN, SUPERVISOR)
- `GET /api/v1/users/{user_id}` — Ver usuario por ID
- `PUT /api/v1/users/{user_id}` — Actualizar nombre
- `PATCH /api/v1/users/{user_id}/role` — Cambiar rol (ADMIN solo)
- `DELETE /api/v1/users/{user_id}` — Eliminar usuario (ADMIN solo)

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
- access_token expira en 30 min, refresh_token en 7 días
- refresh tokens usan rotación: cada refresh invalida el token anterior
