#!/bin/sh
# Arranca como root sólo para preparar el directorio de logs y baja a `app` (N11).
#
# Ese directorio es un bind mount del host (docker-compose.yml). Si no existía, Docker lo crea
# como root, y los logs de despliegues anteriores también son de root: con `USER app` en el
# Dockerfile, Django no podría escribirlos y no arrancaría (RotatingFileHandler). Aquí se le
# dan a `app` y todo lo demás —migrate, collectstatic, gunicorn— corre ya sin privilegios.
#
# `docker compose exec` no pasa por aquí: sigue entrando como root, para tareas de operación.
set -eu

if [ "$(id -u)" = 0 ]; then
    chown -R app:app /usr/src/app/infrastructure/logs/django
    exec setpriv --reuid=app --regid=app --init-groups "$@"
fi

exec "$@"
