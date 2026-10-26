#!/bin/sh
# Mantenimiento diario (N18, AU-17). Lo ejecuta el servicio `maintenance` del compose, con la
# imagen de `web` y su usuario de BD (sólo filas): una vuelta al arrancar y después una cada
# MAINTENANCE_INTERVAL_SECONDS (un día por defecto). Con `--once` hace una vuelta y termina:
#
#   docker compose run --rm maintenance sh infrastructure/maintenance/maintenance.sh --once
#
#   flushexpiredtokens           refresh caducados de la blacklist de simplejwt
#   clearsessions                sesiones Django caducadas
#   cleanup_orphans              filas de ficheros cuyo objeto ya no está en MinIO (sólo NoSuchKey)
#   purge_pending_registrations  altas sin confirmar con el enlace caducado (N17)
#   backup_minio                 copia del bucket en backend/backups/minio
#
# Sin `set -e` a propósito: si un paso falla (MinIO caído, por ejemplo) los demás se ejecutan y
# el bucle sigue. El error queda en el log del servicio.
set -u

INTERVAL="${MAINTENANCE_INTERVAL_SECONDS:-86400}"

run() {
    echo "maintenance: $*"
    python manage.py "$@" || echo "maintenance: ERROR en '$*'" >&2
}

while true; do
    run flushexpiredtokens
    run clearsessions
    run cleanup_orphans
    run purge_pending_registrations
    run backup_minio "${BACKUP_MINIO_DIR:-/backups/minio}"
    [ "${1:-}" = "--once" ] && break
    sleep "$INTERVAL"
done
