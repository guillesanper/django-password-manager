"""
L0 · Secretos y separación de dominios  —  BL1 (resto) + BL2 + .gitignore
(§4.5 BL1/BL2 del PLAN-DE-PRUEBAS.md)

Nivel L0 (§2): todo se lee como **texto**; nada importa Django. Regla de oro de
este fichero: **COMPARA, NUNCA IMPRIME** un secreto. Las aserciones sobre valores
reales sólo afirman igualdad/desigualdad/longitud; jamás vuelcan el contenido, ni
en el mensaje de error.

  BL1 (resto L0): en `.env.example` las DOS URLs de Redis llevan la contraseña y
        apuntan a bases DISTINTAS (/1 caché, /2 sesiones). La parte de settings.py
        (default /1 y /2 desde variables propias) ya la cubre test_config_django.py.

  BL2:  separación de claves por dominio.
        · settings.py: `SESSION_ENCRYPTION_KEY` se lee de su PROPIA variable de
          entorno (antes caía en ENCRYPTION_KEY, reusando una clave para dos
          dominios).
        · **Divergencia verificada contra el código (§1.1):** la vieja
          `ENCRYPTION_KEY` (capa Fernet at-rest de ficheros) se **retiró en el paso
          28** —el at-rest lo aporta ahora la SSE-S3 de MinIO— y NO existe ya como
          asignación viva en settings.py ni en .env.example. Por eso el ejemplo del
          plan ("ENCRYPTION_KEY != SESSION_ENCRYPTION_KEY") ya no es literal: se
          comprueba que ENCRYPTION_KEY no reaparece y, sobre el `.env` real (si
          existe), que las claves de dominios distintos NO comparten valor.

  .gitignore: `.env` está ignorado y NO versionado; sólo la plantilla
        `.env.example` (con placeholders) se versiona.
"""

import re
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.l0

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ENV_EXAMPLE_REL = "backend/.env.example"
_GITIGNORE_REL = ".gitignore"

# .env reales candidatos (gitignored). Pueden no existir en toda máquina: los
# tests que dependen de ellos se SALTAN, no fallan.
_REAL_ENV_CANDIDATES = ["backend/.env", ".env"]


def _parse_env(text: str) -> dict[str, str]:
    """KEY=VALUE por línea; ignora comentarios y líneas en blanco. Sin `export`."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip()
    return out


# =====================================================================
# BL1 (resto) — .env.example: ambas URLs de Redis con contraseña y db distinta
# =====================================================================

@pytest.fixture(scope="module")
def env_example(read_repo_text) -> str:
    return read_repo_text(_ENV_EXAMPLE_REL)


def test_bl1_env_example_redis_urls_con_password_y_db_distinta(env_example):
    env = _parse_env(env_example)
    redis_url = env.get("REDIS_URL", "")
    sessions_url = env.get("REDIS_SESSIONS_URL", "")

    assert redis_url and sessions_url, (
        "Faltan REDIS_URL y/o REDIS_SESSIONS_URL en .env.example (BL1)."
    )
    # La plantilla usa el placeholder <REDIS_PASSWORD>; ambas URLs deben llevarlo.
    for name, url in (("REDIS_URL", redis_url), ("REDIS_SESSIONS_URL", sessions_url)):
        assert "REDIS_PASSWORD" in url, (
            f"{name} de .env.example no incluye la contraseña "
            "(redis://:<REDIS_PASSWORD>@...); Redis quedaría sin auth (BL1)."
        )
    assert redis_url.endswith("/1"), (
        "REDIS_URL de .env.example no apunta a la db 1 (BL1)."
    )
    assert sessions_url.endswith("/2"), (
        "REDIS_SESSIONS_URL de .env.example no apunta a la db 2 (BL1)."
    )
    assert redis_url != sessions_url, (
        "Las dos URLs de Redis en .env.example son idénticas; deben ir a bases "
        "distintas (BL1)."
    )


# =====================================================================
# BL2 — separación de claves de cifrado por dominio (settings.py estático)
# =====================================================================

def test_bl2_session_encryption_key_de_su_propia_env_var(settings_source):
    """SESSION_ENCRYPTION_KEY se lee de la variable SESSION_ENCRYPTION_KEY."""
    assert re.search(
        r"""SESSION_ENCRYPTION_KEY\s*=\s*os\.getenv\(\s*['"]SESSION_ENCRYPTION_KEY['"]""",
        settings_source,
    ), (
        "SESSION_ENCRYPTION_KEY no se lee de su propia variable de entorno; "
        "reutilizar otra clave mezclaría dominios de cifrado (BL2)."
    )


def test_bl2_encryption_key_fernet_retirada(settings_assignments):
    """
    Divergencia §1.1: la vieja ENCRYPTION_KEY (Fernet at-rest) se retiró en el
    paso 28. No debe existir como nombre ASIGNADO en settings.py. Se usa el
    conjunto de nombres del AST: `ENCRYPTION_KEY_ROTATION_DAYS` es otro nombre y no
    cuenta como reaparición.
    """
    names, _ = settings_assignments
    assert "ENCRYPTION_KEY" not in names, (
        "ENCRYPTION_KEY vuelve a estar asignada en settings.py; se retiró en el "
        "paso 28 (redundante sobre el cifrado de cliente + SSE-S3 de MinIO) (BL2)."
    )


def test_bl2_env_example_sin_encryption_key_viva(env_example):
    """En .env.example ENCRYPTION_KEY sólo puede aparecer en el comentario que
    explica su retirada, nunca como asignación `ENCRYPTION_KEY=`."""
    for line in env_example.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not re.match(r"ENCRYPTION_KEY\s*=", stripped), (
            "ENCRYPTION_KEY reaparece como variable en .env.example; se retiró en "
            "el paso 28 (BL2)."
        )


# =====================================================================
# BL2 — .env real (si existe): claves de dominios distintos no comparten valor
#        COMPARA, NUNCA IMPRIME.
# =====================================================================

def _load_real_env() -> dict[str, str] | None:
    for rel in _REAL_ENV_CANDIDATES:
        path = _REPO_ROOT / rel
        if path.is_file():
            return _parse_env(path.read_text(encoding="utf-8"))
    return None


def test_bl2_secretos_reales_no_se_reutilizan_entre_dominios():
    """
    Sobre el `.env` real (gitignored): las claves que protegen dominios distintos
    deben tener valores DISTINTOS entre sí. No se imprime ningún valor: sólo se
    comparan por igualdad y se reporta el NOMBRE de las claves colisionadas.
    """
    env = _load_real_env()
    if env is None:
        pytest.skip(
            "No hay .env real (gitignored) en esta máquina; comparación de "
            "valores omitida. Sólo aplica donde estén las credenciales."
        )

    # Un representante por dominio de seguridad REALMENTE distinto. MinIO va con
    # una sola entrada (MINIO_SECRET_KEY, la que usa Django): .env.example
    # documenta que las credenciales de servicio "pueden coincidir con las root",
    # así que MINIO_ROOT_PASSWORD == MINIO_SECRET_KEY es una coincidencia
    # INTENCIONADA dentro del mismo dominio, no un reuso entre dominios.
    dominios = [
        "DJANGO_SECRET_KEY",
        "SESSION_ENCRYPTION_KEY",
        "POSTGRES_PASSWORD",
        "REDIS_PASSWORD",
        "MINIO_SECRET_KEY",
    ]
    presentes = {k: env[k] for k in dominios if env.get(k)}
    if len(presentes) < 2:
        pytest.skip(
            "Menos de dos secretos de dominio están rellenos en el .env real; "
            "nada que comparar."
        )

    # Agrupar NOMBRES por valor compartido, sin exponer el valor.
    por_valor: dict[str, list[str]] = {}
    for name, value in presentes.items():
        por_valor.setdefault(value, []).append(name)
    colisiones = [sorted(names) for names in por_valor.values() if len(names) > 1]

    assert not colisiones, (
        "Hay claves de dominios distintos que comparten el mismo valor en el .env "
        f"real (reuso de secreto entre dominios): {colisiones}. Deben ser "
        "distintas (BL2). [valores nunca impresos]"
    )


# =====================================================================
# .gitignore — .env ignorado y NO versionado; sólo la plantilla se versiona
# =====================================================================

@pytest.fixture(scope="module")
def gitignore(read_repo_text) -> str:
    return read_repo_text(_GITIGNORE_REL)


def test_gitignore_cubre_env_y_exceptua_la_plantilla(gitignore):
    lineas = [l.strip() for l in gitignore.splitlines()]
    cubre = any(
        pat in lineas for pat in (".env*", "*.env", ".env")
    )
    assert cubre, (
        ".gitignore no ignora los ficheros .env (patrón .env* / *.env). Un "
        "secreto podría acabar versionado (BL2)."
    )
    assert "!.env.example" in lineas, (
        ".gitignore no reexceptúa !.env.example; la plantilla (sólo placeholders) "
        "debe poder versionarse."
    )


def test_gitignore_ningun_env_real_versionado():
    """
    Ningún `.env` real está en el índice de git: sólo `.env.example`. Se consulta
    `git ls-files`; si git no está disponible o no es un repo, se SALTA.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        pytest.skip("git no disponible; no se puede verificar el índice.")
        return

    if out.returncode != 0:
        pytest.skip("`git ls-files` falló (¿fuera de un repo?); verificación omitida.")
        return

    tracked = out.stdout.splitlines()
    ofensivos = [
        f
        for f in tracked
        if re.search(r"(^|/)\.env(\.|$)", f) and not f.endswith(".env.example")
    ]
    assert not ofensivos, (
        f"Hay ficheros .env versionados en git (deberían estar ignorados): "
        f"{ofensivos}. Sólo .env.example debe versionarse (BL2)."
    )
