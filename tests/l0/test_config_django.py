"""
L0 · Configuración estática de Django  —  C5-a, A2-a, A2-b, T1(settings), BL1

Nivel L0 (§2 del PLAN-DE-PRUEBAS.md): se lee `backend/demo/settings.py` como
**texto y AST**; NUNCA se importa Django ni `demo.settings`. Motivos:

  1. settings.py:39 hace `os.environ["DJANGO_SECRET_KEY"]` sin fallback -> importar
     el módulo en el host lanza KeyError.
  2. minio_service.py instancia MinIO a nivel de módulo -> importar la app bloquea
     ~20 s resolviendo `minio`.

`ast.parse` NO ejecuta el módulo, así que leerlo es seguro y, además, es más
estricto que un `import`: comprobamos lo que el fichero *declara*, no lo que la
pila viva tiene en memoria (que ya viene tocada por settings_test en L1).

Trampa 16: `DJANGO_VITE_ASSETS_PATH` aparece en un COMENTARIO de settings.py que
explica su retirada. Por eso T1 comprueba **nombres asignados por AST**, no un
`str in source`: el ajuste no está *asignado* aunque el string exista en la nota.
"""

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.l0

# --- Localización del fichero de settings (repo root = tests/l0/ -> parents[2]) ---
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SETTINGS_PATH = _REPO_ROOT / "backend" / "demo" / "settings.py"


def _read_settings():
    if not _SETTINGS_PATH.is_file():
        raise AssertionError(
            f"No se encuentra settings.py en {_SETTINGS_PATH}. "
            "Este test asume que corre desde la raíz del repo (tests/l0/...)."
        )
    return _SETTINGS_PATH.read_text(encoding="utf-8")


SETTINGS_SRC = _read_settings()
SETTINGS_TREE = ast.parse(SETTINGS_SRC, filename=str(_SETTINGS_PATH))


def _top_level_assignments():
    """
    Recorre SÓLO el cuerpo del módulo (no entra en `if DEBUG:` ni en funciones):

      - names:    conjunto de nombres asignados a nivel de módulo.
      - literals: nombre -> valor, para las asignaciones cuyo lado derecho es un
                  literal evaluable con ast.literal_eval (str, bool, tupla, lista...).
                  Las asignaciones con llamadas (`os.getenv(...)`, `_env_bool(...)`)
                  no entran aquí; ésas se comprueban por texto/regex.

    Al mirar sólo el nivel de módulo, un `CSP_SCRIPT_SRC` reasignado dentro de
    `if DEBUG:` NO pisa el valor de producción: capturamos el de producción.
    """
    names = set()
    literals = {}
    for node in SETTINGS_TREE.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
                try:
                    literals[target.id] = ast.literal_eval(node.value)
                except (ValueError, SyntaxError):
                    pass
    return names, literals


ASSIGNED_NAMES, LITERALS = _top_level_assignments()


# =====================================================================
# C5-a — SECRET_KEY del entorno, DEBUG de _env_bool, sin django-insecure
# =====================================================================

def test_c5a_sin_clave_insegura_por_defecto():
    """La clave `django-insecure-...` del startproject no debe existir en el fichero."""
    assert "django-insecure" not in SETTINGS_SRC, (
        "settings.py conserva la clave 'django-insecure-...' del startproject (C5)."
    )


def test_c5a_secret_key_desde_entorno_sin_fallback():
    """SECRET_KEY = os.environ["DJANGO_SECRET_KEY"] (indexado, sin default)."""
    assert re.search(
        r"""SECRET_KEY\s*=\s*os\.environ\[\s*['"]DJANGO_SECRET_KEY['"]\s*\]""",
        SETTINGS_SRC,
    ), "SECRET_KEY no se lee con os.environ[\"DJANGO_SECRET_KEY\"] (sin fallback) (C5)."


def test_c5a_debug_desde_env_bool():
    """DEBUG se deriva del entorno vía _env_bool, no hardcodeado a True."""
    assert re.search(
        r"""DEBUG\s*=\s*_env_bool\(\s*['"]DJANGO_DEBUG['"]""", SETTINGS_SRC
    ), "DEBUG no se lee con _env_bool('DJANGO_DEBUG', ...) (C5)."


# =====================================================================
# A2-a — CSP activa y estricta en producción
# =====================================================================

def test_a2a_csp_middleware_presente():
    middleware = LITERALS.get("MIDDLEWARE")
    assert isinstance(middleware, list), "MIDDLEWARE no es una lista literal legible."
    assert "csp.middleware.CSPMiddleware" in middleware, (
        "csp.middleware.CSPMiddleware no está en MIDDLEWARE (A2)."
    )


def test_a2a_csp_default_src_self():
    assert LITERALS.get("CSP_DEFAULT_SRC") == ("'self'",), (
        f"CSP_DEFAULT_SRC no es (\"'self'\",): {LITERALS.get('CSP_DEFAULT_SRC')!r} (A2)."
    )


def test_a2a_csp_frame_ancestors_none():
    assert LITERALS.get("CSP_FRAME_ANCESTORS") == ("'none'",), (
        f"CSP_FRAME_ANCESTORS no es (\"'none'\",): "
        f"{LITERALS.get('CSP_FRAME_ANCESTORS')!r} (A2)."
    )


def test_a2a_script_src_produccion_sin_unsafe_eval():
    """
    El valor de MÓDULO (producción) de CSP_SCRIPT_SRC no lleva unsafe-eval ni
    unsafe-inline. La excepción de desarrollo vive dentro de `if DEBUG:`, que este
    barrido de nivel de módulo no captura a propósito.
    """
    script_src = LITERALS.get("CSP_SCRIPT_SRC")
    assert script_src == ("'self'",), (
        f"CSP_SCRIPT_SRC de producción no es (\"'self'\",): {script_src!r}. "
        "Un XSS podría ejecutar JS si lleva unsafe-inline/unsafe-eval (A2)."
    )


# =====================================================================
# A2-b — HttpOnly de sesión; CSRF legible a propósito (double-submit)
# =====================================================================

def test_a2b_session_cookie_httponly_true():
    assert LITERALS.get("SESSION_COOKIE_HTTPONLY") is True, (
        "SESSION_COOKIE_HTTPONLY debe ser True: la cookie de sesión no debe ser "
        "legible desde JS (A2)."
    )


def test_a2b_csrf_cookie_httponly_false_a_proposito():
    """
    CSRF_COOKIE_HTTPONLY = False es deliberado: el patrón double-submit necesita
    que el JS lea la cookie para copiarla en X-CSRFToken. No es una fuga.
    """
    assert LITERALS.get("CSRF_COOKIE_HTTPONLY") is False, (
        "CSRF_COOKIE_HTTPONLY debe ser False (double-submit); ver comentario en "
        "settings.py (A2)."
    )


# =====================================================================
# T1 (settings) — django-vite 3.x: sin DJANGO_VITE_ASSETS_PATH, con MANIFEST_PATH
# =====================================================================

def test_t1_sin_django_vite_assets_path_asignado():
    """
    Trampa 16: el string 'DJANGO_VITE_ASSETS_PATH' aparece en un comentario que
    explica su retirada. Comprobamos que NO es un nombre *asignado* (AST), no que
    el string no exista.
    """
    assert "DJANGO_VITE_ASSETS_PATH" not in ASSIGNED_NAMES, (
        "DJANGO_VITE_ASSETS_PATH sigue asignado en settings.py; en django-vite 3.x "
        "es un ajuste muerto (T1)."
    )


def test_t1_manifest_path_asignado():
    assert "DJANGO_VITE_MANIFEST_PATH" in ASSIGNED_NAMES, (
        "Falta DJANGO_VITE_MANIFEST_PATH, que es quien decide de dónde se lee el "
        "manifest en django-vite 3.x (T1)."
    )


# =====================================================================
# BL1 (parte L0) — Redis default y sesiones en bases DISTINTAS, de env vars DISTINTAS
# =====================================================================

def _extract_default(env_var):
    """Extrae el default de `os.getenv('<env_var>', '<default>')` del texto."""
    m = re.search(
        r"""os\.getenv\(\s*['"]%s['"]\s*,\s*['"]([^'"]+)['"]""" % re.escape(env_var),
        SETTINGS_SRC,
    )
    return m.group(1) if m else None


def test_bl1_redis_default_db1():
    default = _extract_default("REDIS_URL")
    assert default is not None, "No se encuentra el default de REDIS_URL en settings.py."
    assert default.endswith("/1"), (
        f"El default de REDIS_URL debería apuntar a la db 1, no {default!r} (BL1)."
    )


def test_bl1_sessions_lee_su_propia_env_var_db2():
    """
    La caché `sessions` debe leer REDIS_SESSIONS_URL (variable propia) con default a
    la db 2. El bug de BL1 era que caía en REDIS_URL con un default engañoso, así que
    en cuanto REDIS_URL estaba definida ambas cachés compartían la db 1.
    """
    assert re.search(
        r"""os\.getenv\(\s*['"]REDIS_SESSIONS_URL['"]""", SETTINGS_SRC
    ), "La caché de sesiones no lee su propia variable REDIS_SESSIONS_URL (BL1)."

    sessions_default = _extract_default("REDIS_SESSIONS_URL")
    assert sessions_default is not None, (
        "No se encuentra el default de REDIS_SESSIONS_URL en settings.py."
    )
    assert sessions_default.endswith("/2"), (
        f"El default de REDIS_SESSIONS_URL debería apuntar a la db 2, no "
        f"{sessions_default!r} (BL1)."
    )


def test_bl1_default_y_sessions_en_bases_distintas():
    redis_default = _extract_default("REDIS_URL")
    sessions_default = _extract_default("REDIS_SESSIONS_URL")
    assert redis_default != sessions_default, (
        f"Las cachés `default` y `sessions` comparten LOCATION por defecto "
        f"({redis_default!r}); deben estar en bases Redis distintas (BL1)."
    )
