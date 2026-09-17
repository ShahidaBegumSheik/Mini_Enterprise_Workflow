# MECWF Backend

Microservices monorepo for the Mini Enterprise Collaboration and Workflow project.

## Architecture

Three FastAPI microservices share one MySQL server container, each with its own database on it:

| Service | Port | Database | Responsibility | Owner |
|---|---:|---|---|---|
| Authentication Service | 8001 | `auth_db` | Registration, OTP, login/logout, refresh, forgot/reset password, internal token validation | This repo (implemented) |
| User Service | 8002 | `user_db` | User profile, account settings, individual dashboard | Teammate-owned (not yet implemented) |
| Tenant Admin Service | 8003 | `tenant_admin_db` | Tenants, memberships, invitations, roles, audit logs | Teammate-owned (not yet implemented) |
| MySQL | 3307 | — | One server, three databases | — |

Each service connects only to its own database — set via its own `DATABASE_URL` in its `.env` — and only that service's Alembic migrations run against it.

## Layout

```
backend/
├── docker-compose.yml          # mysql + authentication-service + api-gateway
├── .env.example                # shared infra/security values
├── db-init/
│   └── init-databases.sh       # creates auth_db, user_db, tenant_admin_db + scoped users
├── gateway/
│   └── nginx.conf              # API gateway (port 8000) -> services
└── services/
    ├── authentication-service/ # implemented
    ├── user-service/           # teammate-owned placeholder
    └── tenant-admin-service/   # teammate-owned placeholder
```

## Environment files

Create each `.env` from its `.env.example`. Existing `.env` files must never be committed.

```powershell
Copy-Item .env.example .env
Copy-Item services/authentication-service/.env.example services/authentication-service/.env
```

The root `.env` holds shared infrastructure values only (MySQL root password, one
scoped DB user/password per service, `INTERNAL_API_KEY`). Each service's `.env`
holds its own service-specific configuration.

## Start

```powershell
docker compose up --build -d
docker compose ps
```

Swagger:

- Authentication: http://localhost:8001/docs
- Gateway: http://localhost:8000

`db-init/init-databases.sh` only runs the first time the `db` container starts
against an empty volume. Each service applies its own Alembic migrations at boot:

- `alembic_version_auth` (in `auth_db`)
- `alembic_version_user` (in `user_db`)
- `alembic_version_tenant` (in `tenant_admin_db`)

## Authentication Service

Owns (read/write): `auth_credentials`, `otp_flows`, `refresh_sessions` in `auth_db`.

Public API under `/api/v1/auth/*`:
`register`, `verify-otp`, `resend-otp`, `login`, `refresh-token`, `logout`,
`forgot-password`, `verify-forgot-otp`, `resend-forgot-otp`, `reset-password`, `me`.

Internal API (hidden from OpenAPI, guarded by `X-Internal-API-Key`):
`POST /api/v1/auth/internal/validate-token`, `GET .../internal/credentials/by-email`,
`GET .../internal/credentials/by-user-id`.

The User Service (`POST /api/v1/internal/users`) and Tenant Admin Service
(`POST /api/v1/internal/organizations`) are called only through HTTPX client
contracts in `app/clients/`; their behavior is implemented by the owning teams.

## Data ownership

For every shared table/entity, exactly one service is the source of truth and may
write to it. Other services only ever reach it through that service's internal
API (`X-Internal-API-Key`-protected), never through a cross-database read or write.
The per-database scoped MySQL users (see `db-init/`) enforce this at the database
layer as well.