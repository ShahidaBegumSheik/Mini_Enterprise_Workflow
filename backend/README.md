# MECWF Backend

Microservices monorepo for the Mini Enterprise Collaboration and Workflow project.

## Architecture

Three FastAPI microservices share one MySQL server container, each with its own database on it:

| Service | Port | Database | Responsibility | Owner |
|---|:--:|---:|---|---|
| Authentication Service | 8001 | `auth_db` | Registration with email OTP verification | This repo (implemented) |
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

Owns (read/write): `auth_credentials` in `auth_db`. The registration/OTP flow is
fully stateless — the OTP and the registration payload travel encrypted
(Fernet) inside a signed, short-lived `otp_token` HTTP-only cookie. Nothing
except the final credential is ever persisted.

Public API under `/api/v1/auth/*`:

- `POST /register` — validate registration, encrypt the flow, email the OTP
- `POST /verify-otp` — verify the OTP, create the user (and organization for
  organization accounts) through the internal service contracts
- `POST /resend-otp` — send a new OTP (bounded resends, same expiry)

Account-type email rules: individual accounts must use a personal email domain
(gmail/yahoo/outlook/hotmail/icloud); organization accounts must use an official
business domain and a mandatory `organization_name`.

After successful verification the User Service
(`POST /api/v1/internal/users`) and Tenant Admin Service
(`POST /api/v1/internal/organizations`) are called only through HTTPX client
contracts in `app/clients/`; their behavior is implemented by the owning teams.

## Data ownership

For every shared table/entity, exactly one service is the source of truth and may
write to it. Other services only ever reach it through that service's internal
API (`X-Internal-API-Key`-protected), never through a cross-database read or write.
The per-database scoped MySQL users (see `db-init/`) enforce this at the database
layer as well.