# syntax=docker/dockerfile:1
#
# MECWF Authentication Service
#
# Multi-stage build:
#   builder - creates a minimal virtualenv with only the pinned runtime
#             dependencies (no OS package manager, no build toolchain leaked
#             into the final image).
#   runtime - copies that virtualenv plus the application source; runs as a
#             non-root user.
#
# No .env files or secrets are ever copied into the image. All runtime
# configuration (DATABASE_URL, JWT_SECRET_KEY, service URLs, ...) is supplied
# through container environment variables by Docker Compose.

# ---------- Stage 1: build the locked runtime virtualenv ----------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt

# ---------- Stage 2: runtime ----------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv

COPY alembic ./alembic
COPY alembic.ini ./
COPY app ./app

# Non-root service user. UID/GID match the app data volume owner expectations.
RUN groupadd --gid 10001 --system app \
    && useradd --uid 10001 --gid app --system --no-create-home --home-dir /app app \
    && chown -R 10001:10001 /app

USER 10001:10001

# The application port. Overridable at runtime via AUTHENTICATION_SERVICE_PORT
# (e.g. from the host Compose environment).
ENV AUTHENTICATION_SERVICE_PORT=8001
EXPOSE 8001

# Alembic migrations run at startup on the ready database (owner single
# replica: the Compose `db` health gate + idempotent `upgrade head` make this
# safe for this team's one-instance-per-service topology), then uvicorn serves
# the API. Variable expansion happens inside the container shell.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port \"${AUTHENTICATION_SERVICE_PORT:-8001}\""]

# Liveness: /health reflects application availability only; it does not probe
# the Notification Service or any other optional dependency.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('AUTHENTICATION_SERVICE_PORT','8001')+'/health', timeout=3)"]