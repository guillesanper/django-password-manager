"""L1 — la aplicación no se conecta a Postgres con un usuario que puede cambiar el esquema (N18).

AU-27: la app y el exportador usaban el superusuario del initdb. Una inyección SQL, o un fallo
cualquiera en la app, tenía DDL completo: borrar tablas, crear funciones, leer otras bases.

Ahora `infrastructure/postgres/apply-roles.sh` (servicio `db-roles` del compose) crea tres
usuarios y los deja así:

  - migraciones: dueño del esquema `public`; sólo lo usa el servicio `migrate`;
  - app: lee y escribe filas, nada más; es el único que recibe `web`;
  - monitor: `pg_monitor`, para el exportador de Prometheus.

El test aplica el script de verdad contra el Postgres local, en una base temporal, en los dos
casos: una instalación nueva (roles antes de migrar) y una existente (tablas creadas antes por
el superusuario). Necesita `psql` y un usuario con permiso para crear roles: dentro de `web`
(que ya no lo tiene) se salta.
"""

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from django.conf import settings
from psycopg import errors

BACKEND = Path(__file__).resolve().parents[2]
SCRIPT = BACKEND / "infrastructure" / "postgres" / "apply-roles.sh"

ROLES = {
    "DB_MIGRATE_USER": "n18_migraciones",
    "DB_MIGRATE_PASSWORD": "migr-Clave-1",
    "DB_USER": "n18_app",
    "DB_PASSWORD": "app-Clave-1",
    "DB_MONITOR_USER": "n18_monitor",
    "DB_MONITOR_PASSWORD": "mon-Clave-1",
}


def _admin_conn(dbname=None):
    db = settings.DATABASES["default"]
    return psycopg.connect(
        host=db["HOST"], port=db["PORT"], user=db["USER"], password=db["PASSWORD"],
        dbname=dbname or db["NAME"], autocommit=True,
    )


def _puede_crear_roles():
    try:
        with _admin_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user")
            return bool(cur.fetchone()[0])
    except psycopg.Error:
        return False


pytestmark = [
    pytest.mark.l1,
    pytest.mark.skipif(shutil.which("psql") is None, reason="sin psql"),
    pytest.mark.skipif(not _puede_crear_roles(), reason="el usuario de la BD no puede crear roles"),
]


def _env(dbname, **extra):
    db = settings.DATABASES["default"]
    env = dict(os.environ)
    env.update(ROLES)
    env.update(
        POSTGRES_DB=dbname, POSTGRES_USER=db["USER"], POSTGRES_PASSWORD=db["PASSWORD"],
        DB_HOST=db["HOST"], DB_PORT=str(db["PORT"]),
    )
    env.update(extra)
    return env


def _aplicar_roles(dbname, **extra):
    r = subprocess.run(["sh", str(SCRIPT)], env=_env(dbname, **extra),
                       capture_output=True, text=True, check=False, timeout=60)
    assert r.returncode == 0, f"apply-roles.sh falló:\n{r.stdout}\n{r.stderr}"


def _migrar(dbname, user, password):
    env = _env(dbname, DB_USER=user, DB_PASSWORD=password,
               DJANGO_SETTINGS_MODULE="myapp.tests.settings_test")
    r = subprocess.run([sys.executable, "manage.py", "migrate", "--noinput", "-v0"],
                       cwd=BACKEND, env=env, capture_output=True, text=True, check=False, timeout=300)
    assert r.returncode == 0, f"migrate como {user} falló:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"


def _conectar(dbname, user, password):
    db = settings.DATABASES["default"]
    return psycopg.connect(host=db["HOST"], port=db["PORT"], user=user, password=password,
                           dbname=dbname, autocommit=True)


@pytest.fixture
def base_temporal():
    nombre = f"n18_{uuid.uuid4().hex[:8]}"
    with _admin_conn() as conn, conn.cursor() as cur:
        cur.execute(f'CREATE DATABASE "{nombre}"')
    yield nombre
    with _admin_conn() as conn, conn.cursor() as cur:
        cur.execute(f'DROP DATABASE IF EXISTS "{nombre}" WITH (FORCE)')
        for clave in ("DB_USER", "DB_MONITOR_USER", "DB_MIGRATE_USER"):
            cur.execute(f'DROP ROLE IF EXISTS "{ROLES[clave]}"')


def _comprobar_app_solo_filas(dbname):
    with _conectar(dbname, ROLES["DB_USER"], ROLES["DB_PASSWORD"]) as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO auth_group (name) VALUES ('n18') RETURNING id")
        cur.execute("UPDATE auth_group SET name = 'n18b' WHERE name = 'n18'")
        cur.execute("SELECT count(*) FROM auth_group")
        cur.execute("DELETE FROM auth_group WHERE name = 'n18b'")

        for ddl in (
            "CREATE TABLE n18_intruso (id int)",
            "DROP TABLE auth_group",
            "ALTER TABLE auth_user ADD COLUMN n18 int",
            "TRUNCATE auth_group",
        ):
            with pytest.raises((errors.InsufficientPrivilege,)):
                cur.execute(ddl)

        cur.execute("SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = current_user")
        assert cur.fetchone() == (False, False, False)


def _tablas_ajenas(dbname):
    with _admin_conn(dbname) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'S', 'v', 'm') "
            "AND pg_get_userbyid(c.relowner) <> %s",
            [ROLES["DB_MIGRATE_USER"]],
        )
        return [r[0] for r in cur.fetchall()]


def test_n18_instalacion_nueva(base_temporal):
    _aplicar_roles(base_temporal)
    _migrar(base_temporal, ROLES["DB_MIGRATE_USER"], ROLES["DB_MIGRATE_PASSWORD"])

    assert _tablas_ajenas(base_temporal) == []
    _comprobar_app_solo_filas(base_temporal)


def test_n18_instalacion_existente_y_reaplicar(base_temporal):
    """Las bases anteriores a N18 tienen las tablas del superusuario: pasan al de migraciones,
    que puede seguir migrando, y la app sólo toca filas. Reaplicar el script no rompe nada y
    actualiza las contraseñas."""
    db = settings.DATABASES["default"]
    _migrar(base_temporal, db["USER"], db["PASSWORD"])
    assert _tablas_ajenas(base_temporal), "el montaje del test debía dejar tablas del superusuario"

    _aplicar_roles(base_temporal)
    assert _tablas_ajenas(base_temporal) == []
    _migrar(base_temporal, ROLES["DB_MIGRATE_USER"], ROLES["DB_MIGRATE_PASSWORD"])
    _comprobar_app_solo_filas(base_temporal)

    _aplicar_roles(base_temporal, DB_PASSWORD="app-Clave-2")
    with _conectar(base_temporal, ROLES["DB_USER"], "app-Clave-2") as conn, conn.cursor() as cur:
        cur.execute("SELECT 1")


def test_n18_monitor_y_migraciones_sin_superpoderes(base_temporal):
    _aplicar_roles(base_temporal)
    with _admin_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT rolname, rolsuper, rolcreaterole FROM pg_roles WHERE rolname = ANY(%s)",
            [[ROLES["DB_MIGRATE_USER"], ROLES["DB_USER"], ROLES["DB_MONITOR_USER"]]],
        )
        assert {r[0]: r[1:] for r in cur.fetchall()} == {
            ROLES[k]: (False, False) for k in ("DB_MIGRATE_USER", "DB_USER", "DB_MONITOR_USER")
        }
        cur.execute("SELECT pg_has_role(%s, 'pg_monitor', 'member')", [ROLES["DB_MONITOR_USER"]])
        assert cur.fetchone()[0] is True


def test_n18_el_script_rechaza_reutilizar_el_superusuario(base_temporal):
    db = settings.DATABASES["default"]
    r = subprocess.run(["sh", str(SCRIPT)], env=_env(base_temporal, DB_USER=db["USER"]),
                       capture_output=True, text=True, check=False, timeout=60)
    assert r.returncode != 0, "aceptó que la app use el superusuario"
