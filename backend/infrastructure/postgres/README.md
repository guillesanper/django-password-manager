# Postgres: usuarios, copias y restauración (N18)

## Usuarios

| Usuario | Dónde está | Para qué |
|---|---|---|
| `POSTGRES_USER` | `backend/.env.db` | Superusuario del initdb. Sólo lo usa `db-roles`. |
| `DB_MIGRATE_USER` | `backend/.env.db` | Dueño del esquema. Lo usan `migrate` y `backup`. |
| `DB_USER` | `backend/.env` | La aplicación (`web`, `maintenance`): lee y escribe filas, sin DDL. |
| `DB_MONITOR_USER` | `backend/.env` | `postgres-exporter`, con `pg_monitor`. |

`db-roles` ejecuta `apply-roles.sh` en cada arranque: crea los usuarios que falten, les pone la
contraseña que digan los `.env` y pasa al usuario de migraciones lo que creó antes el
superusuario. Para rotar una contraseña basta con cambiarla en su `.env` y volver a levantar.

### Instalación anterior a N18

1. `cp .env.db.example .env.db` y mueve a `.env.db` los valores de `POSTGRES_USER` y
   `POSTGRES_PASSWORD` que había en `.env` (los mismos: el volumen ya existe con ellos).
2. Rellena `DB_MIGRATE_PASSWORD` en `.env.db`, y `DB_USER`, `DB_PASSWORD`, `DB_MONITOR_USER` y
   `DB_MONITOR_PASSWORD` en `.env`.
3. `docker compose up -d`. `db-roles` reparte las tablas y `migrate` sigue donde estaba.

### L1 dentro de Docker

`web` ya no puede crear la base de test (su usuario no tiene `CREATEDB`). L1 se lanza con el
usuario de migraciones, desde el servicio `migrate`:

```
docker compose run --rm migrate sh -c \
  'pip install -q -r requirements-dev.txt && DB_USER="$DB_MIGRATE_USER" DB_PASSWORD="$DB_MIGRATE_PASSWORD" pytest myapp/tests'
```

## Copias

- **Base de datos:** el servicio `backup` hace un `pg_dump` al arrancar y después cada día en
  `backend/backups/postgres/<base>-<fecha UTC>.dump`, y borra las de más de 7 días
  (`BACKUP_RETENTION_DAYS`, `BACKUP_INTERVAL_SECONDS`). Una copia a mano:
  `docker compose run --rm backup sh /postgres/backup.sh --once`.
- **Ficheros:** el servicio `maintenance` copia cada día el bucket en `backend/backups/minio/`.
  No borra de la copia lo que se borre del bucket.

Las dos están **en la misma máquina**: protegen de un volumen roto o de un borrado, no de perder
el disco. Para eso hay que llevarlas a otro sitio (copiar `backend/backups/`).

El volcado no va cifrado. Las contraseñas y los ficheros son cifrado de cliente (el servidor no
tiene la clave), pero la copia lleva emails, hashes de login y la actividad.

## Restaurar

Base de datos, sobre una base vacía (por ejemplo tras borrar el volumen `postgres_data`).
`--no-deps` es necesario: sin él arrancaría antes `migrate`, que crearía las tablas vacías y el
`pg_restore` chocaría con ellas.

```
docker compose up -d db
docker compose run --rm db-roles
docker compose run --rm --no-deps backup sh -c \
  'PGPASSWORD="$DB_MIGRATE_PASSWORD" pg_restore --no-owner -h db -U "$DB_MIGRATE_USER" -d "$POSTGRES_DB" /backups/<fichero>.dump'
docker compose run --rm db-roles   # vuelve a dar permisos a la app sobre lo restaurado
docker compose up -d
```

Ficheros (sube los que falten en el bucket; no toca los que ya están):

```
docker compose run --rm maintenance python manage.py backup_minio /backups/minio --restore
```

## Claves que hay que guardar fuera de la máquina

- `MINIO_KMS_SECRET_KEY`: sin ella, los objetos del **volumen** de MinIO no se pueden leer. La
  copia de `backups/minio/` no la necesita (se baja ya descifrada del SSE-S3).
- Las contraseñas de `.env` y `.env.db`: sin ellas se pueden poner otras, pero hay que
  reconfigurar los servicios.
- `DJANGO_SECRET_KEY`: perderla sólo invalida sesiones y enlaces de activación pendientes.

Ninguna de estas claves descifra las contraseñas de los usuarios: eso sólo lo hace la
contraseña maestra de cada uno, que el servidor no tiene.
