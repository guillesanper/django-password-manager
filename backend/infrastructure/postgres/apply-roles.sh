#!/bin/sh
# Crea o actualiza los usuarios de Postgres de la aplicación (N18, AU-27). Lo ejecuta el
# servicio `db-roles` en cada arranque, con el superusuario del initdb, antes de `migrate`.
# Es idempotente: sobre un volumen anterior a N18 pasa las tablas al usuario de migraciones.
#
#   DB_MIGRATE_USER  dueño del esquema; sólo lo usa el servicio `migrate`.
#   DB_USER          la aplicación: lee y escribe filas, sin DDL.
#   DB_MONITOR_USER  el exportador de Prometheus (pg_monitor).
#
# Las contraseñas del superusuario y de migraciones viven en backend/.env.db, que `web` no lee.
set -eu

: "${POSTGRES_DB:?}" "${POSTGRES_USER:?}" "${POSTGRES_PASSWORD:?}"
: "${DB_MIGRATE_USER:?falta DB_MIGRATE_USER (backend/.env.db)}" "${DB_MIGRATE_PASSWORD:?falta DB_MIGRATE_PASSWORD (backend/.env.db)}"
: "${DB_USER:?falta DB_USER (backend/.env)}" "${DB_PASSWORD:?falta DB_PASSWORD (backend/.env)}"
: "${DB_MONITOR_USER:?falta DB_MONITOR_USER (backend/.env)}" "${DB_MONITOR_PASSWORD:?falta DB_MONITOR_PASSWORD (backend/.env)}"

# Cuatro usuarios distintos: si la app reutilizase el superusuario o el de migraciones, esto
# no separaría nada.
n=$(printf '%s\n' "$POSTGRES_USER" "$DB_MIGRATE_USER" "$DB_USER" "$DB_MONITOR_USER" | sort -u | wc -l)
if [ "$n" -ne 4 ]; then
    echo "apply-roles: POSTGRES_USER, DB_MIGRATE_USER, DB_USER y DB_MONITOR_USER deben ser distintos" >&2
    exit 1
fi

export PGPASSWORD="$POSTGRES_PASSWORD"
exec psql -X -q -v ON_ERROR_STOP=1 \
    -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v db="$POSTGRES_DB" \
    -v migrate_user="$DB_MIGRATE_USER" -v migrate_password="$DB_MIGRATE_PASSWORD" \
    -v app_user="$DB_USER" -v app_password="$DB_PASSWORD" \
    -v monitor_user="$DB_MONITOR_USER" -v monitor_password="$DB_MONITOR_PASSWORD" \
    -f "$(dirname "$0")/roles.sql"
