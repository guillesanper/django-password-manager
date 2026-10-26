#!/bin/sh
# Copia de la base de datos (N18, AU-17). La ejecuta el servicio `backup` del compose: una
# copia al arrancar y después una cada BACKUP_INTERVAL_SECONDS (un día por defecto). Con
# `--once` hace una sola y termina (para probarlo o lanzarla a mano).
#
#   docker compose run --rm backup sh /postgres/backup.sh --once
#
# Formato custom de pg_dump (comprimido, se restaura con pg_restore; ver
# infrastructure/postgres/README.md). Se conecta como el usuario de migraciones, dueño de todas
# las tablas. Las copias de más de BACKUP_RETENTION_DAYS días se borran.
#
# El volcado NO va cifrado: las contraseñas y los ficheros ya son cifrado de cliente (el
# servidor no tiene la clave), pero la copia lleva emails, hashes de login y la actividad. Sólo
# la puede leer root (umask 077).
set -eu

: "${POSTGRES_DB:?}" "${DB_MIGRATE_USER:?}" "${DB_MIGRATE_PASSWORD:?}"
DEST="${BACKUP_DIR:-/backups}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"

umask 077
export PGPASSWORD="$DB_MIGRATE_PASSWORD"

backup_once() {
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    final="$DEST/$POSTGRES_DB-$stamp.dump"
    # A un fichero temporal y renombrado al final: una copia a medias (disco lleno, base caída)
    # nunca se confunde con una buena ni hace que se borre la última que sí lo es. Los fallos se
    # comprueban a mano: llamada desde `backup_once || …`, `set -e` no se aplica dentro.
    if ! pg_dump --format=custom --no-owner \
            -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" -U "$DB_MIGRATE_USER" -d "$POSTGRES_DB" \
            -f "$final.part"; then
        rm -f "$final.part"
        return 1
    fi
    mv "$final.part" "$final" || return 1
    echo "backup: $final"
    find "$DEST" -maxdepth 1 -name "$POSTGRES_DB-*.dump" -mtime "+$RETENTION_DAYS" -print -delete
}

mkdir -p "$DEST"
if [ "${1:-}" = "--once" ]; then
    backup_once
    exit $?
fi

while true; do
    # Un fallo no para el servicio: se registra y se reintenta en la siguiente vuelta.
    backup_once || echo "backup: ERROR, la copia de $(date -u +%FT%TZ) ha fallado" >&2
    sleep "$INTERVAL"
done
