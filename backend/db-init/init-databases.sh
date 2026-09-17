#!/bin/bash
# Creates one database per microservice on the single shared MySQL server,
# and one dedicated database user per service, each granted access ONLY to
# that service's own database.
#
# This is the actual enforcement mechanism behind "exactly one owner
# service per table": app-level discipline (each service only imports its
# own models, only calls its own repository) is necessary but not
# sufficient on its own. Giving each service credentials that MySQL itself
# will only honor against its own database means a bug that tried to
# connect a service to another service's database would be rejected at
# the database layer, not just avoided by convention.
#
# Runs automatically on first container start (MySQL only executes
# /docker-entrypoint-initdb.d scripts against a fresh, empty data directory).
set -euo pipefail

mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<-SQL
    CREATE DATABASE IF NOT EXISTS auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE DATABASE IF NOT EXISTS user_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE DATABASE IF NOT EXISTS tenant_admin_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

    CREATE USER IF NOT EXISTS '${AUTH_DB_USER}'@'%' IDENTIFIED BY '${AUTH_DB_PASSWORD}';
    CREATE USER IF NOT EXISTS '${USER_DB_USER}'@'%' IDENTIFIED BY '${USER_DB_PASSWORD}';
    CREATE USER IF NOT EXISTS '${TENANT_ADMIN_DB_USER}'@'%' IDENTIFIED BY '${TENANT_ADMIN_DB_PASSWORD}';

    GRANT ALL PRIVILEGES ON auth_db.* TO '${AUTH_DB_USER}'@'%';
    GRANT ALL PRIVILEGES ON user_db.* TO '${USER_DB_USER}'@'%';
    GRANT ALL PRIVILEGES ON tenant_admin_db.* TO '${TENANT_ADMIN_DB_USER}'@'%';

    FLUSH PRIVILEGES;
SQL