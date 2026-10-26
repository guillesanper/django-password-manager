"""L1 — copias de seguridad (N18, AU-17).

No había ninguna: ni `pg_dump` ni copia de MinIO. Perder el volumen era perderlo todo.

  - `infrastructure/postgres/backup.sh` (servicio `backup`): `pg_dump` en formato custom con
    el usuario de migraciones, escrito a un temporal y renombrado; borra las copias de más de
    BACKUP_RETENTION_DAYS días; si falla no deja nada a medias ni borra las buenas. Se ejecuta
    de verdad contra el Postgres local y se restaura en otra base.
"""

import os
import shutil
import subprocess
import time
import uuid

import pytest
from django.conf import settings

from .test_roles_postgres import (
    BACKEND,
    ROLES,
    _admin_conn,
    _aplicar_roles,
    _conectar,
    _env,
    _migrar,
    _puede_crear_roles,
    base_temporal,  # noqa: F401  (fixture)
)

BACKUP = BACKEND / "infrastructure" / "postgres" / "backup.sh"

pytestmark = [
    pytest.mark.l1,
    pytest.mark.skipif(shutil.which("pg_dump") is None, reason="sin pg_dump"),
    pytest.mark.skipif(not _puede_crear_roles(), reason="el usuario de la BD no puede crear roles"),
]


def _copia(dbname, destino, **extra):
    return subprocess.run(
        ["sh", str(BACKUP), "--once"],
        env=_env(dbname, BACKUP_DIR=str(destino), **extra),
        capture_output=True, text=True, check=False, timeout=120,
    )


@pytest.fixture
def base_con_datos(base_temporal):  # noqa: F811
    _aplicar_roles(base_temporal)
    _migrar(base_temporal, ROLES["DB_MIGRATE_USER"], ROLES["DB_MIGRATE_PASSWORD"])
    with _admin_conn(base_temporal) as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO auth_group (name) VALUES ('copia-n18')")
    return base_temporal


def test_n18_la_copia_se_restaura(base_con_datos, tmp_path):
    """Sigue el procedimiento de infrastructure/postgres/README.md: base vacía, `db-roles`,
    `pg_restore` como usuario de migraciones, `db-roles` otra vez, y la app vuelve a escribir."""
    r = _copia(base_con_datos, tmp_path)
    assert r.returncode == 0, r.stderr
    copias = sorted(tmp_path.glob(f"{base_con_datos}-*.dump"))
    assert len(copias) == 1 and not list(tmp_path.glob("*.part"))
    assert oct(copias[0].stat().st_mode & 0o777) == "0o600", "la copia debe ser sólo del dueño"

    restaurada = f"n18r_{uuid.uuid4().hex[:8]}"
    db = settings.DATABASES["default"]
    with _admin_conn() as conn, conn.cursor() as cur:
        cur.execute(f'CREATE DATABASE "{restaurada}"')
    try:
        _aplicar_roles(restaurada)
        env = dict(os.environ, PGPASSWORD=ROLES["DB_MIGRATE_PASSWORD"])
        r = subprocess.run(
            ["pg_restore", "--no-owner", "-h", db["HOST"], "-p", str(db["PORT"]),
             "-U", ROLES["DB_MIGRATE_USER"], "-d", restaurada, str(copias[0])],
            env=env, capture_output=True, text=True, check=False, timeout=120,
        )
        assert r.returncode == 0, r.stderr
        _aplicar_roles(restaurada)

        with _conectar(restaurada, ROLES["DB_USER"], ROLES["DB_PASSWORD"]) as conn, \
                conn.cursor() as cur:
            cur.execute("SELECT name FROM auth_group")
            assert cur.fetchall() == [("copia-n18",)]
            cur.execute("INSERT INTO auth_group (name) VALUES ('tras-restaurar')")
    finally:
        with _admin_conn() as conn, conn.cursor() as cur:
            cur.execute(f'DROP DATABASE IF EXISTS "{restaurada}" WITH (FORCE)')


def test_n18_retencion(base_con_datos, tmp_path):
    vieja = tmp_path / f"{base_con_datos}-20200101T000000Z.dump"
    reciente = tmp_path / f"{base_con_datos}-20990101T000000Z.dump"
    ajena = tmp_path / "otra-cosa.dump"
    for f in (vieja, reciente, ajena):
        f.write_bytes(b"x")
    hace_10_dias = time.time() - 10 * 86400
    for f in (vieja, ajena):
        os.utime(f, (hace_10_dias, hace_10_dias))

    assert _copia(base_con_datos, tmp_path, BACKUP_RETENTION_DAYS="7").returncode == 0
    assert not vieja.exists(), "la copia de hace 10 días debía borrarse"
    assert reciente.exists() and ajena.exists()


def test_n18_una_copia_fallida_no_deja_nada_ni_borra(base_con_datos, tmp_path):
    vieja = tmp_path / f"{base_con_datos}-20200101T000000Z.dump"
    vieja.write_bytes(b"x")
    hace_10_dias = time.time() - 10 * 86400
    os.utime(vieja, (hace_10_dias, hace_10_dias))

    r = _copia(base_con_datos, tmp_path, DB_MIGRATE_PASSWORD="incorrecta")
    assert r.returncode != 0
    assert [p.name for p in tmp_path.iterdir()] == [vieja.name], (
        "una copia fallida no debe dejar ficheros ni aplicar la retención"
    )
