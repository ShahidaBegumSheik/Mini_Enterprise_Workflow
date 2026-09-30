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

Owns (read/write) `auth_credentials`, `refresh_sessions` and `password_resets`
in `auth_db` (its own database, using its own Alembic chain headed by
`alembic_version_auth`). It never creates foreign keys into, or reads from, the
User Service or Tenant Admin Service databases — `user_id` / `organization_id`
are stored only as plain external identifiers.

Persistence is strictly auth-owned, safe metadata:

- `auth_credentials` — the credentials needed to authenticate a principal. The
  password is stored **only** as a bcrypt `password_hash`; never plaintext.
- `refresh_sessions` — one row per issued refresh token; stores the token's
  `jti` plus a SHA-256 `token_hash`, issuance/expiry/revocation times and the
  `replaced_by` chain for rotation. Never stores the raw refresh token.
- `password_resets` — single-use reset-flow metadata; only a SHA-256
  `token_hash` and the `consumed_at` marker. Never stores the reset JWT.

The registration/OTP and forgot-password OTP flows are fully stateless — the
OTP and the flow payload travel encrypted (Fernet) inside signed, short-lived
HTTP-only cookies (`otp_token`, `reset_otp_token`). No `otp_verifications`
table exists and no raw OTP is ever persisted. OTP emails are delivered via the
Notification Service (`POST /api/v1/internal/notifications`), never raw SMTP.

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