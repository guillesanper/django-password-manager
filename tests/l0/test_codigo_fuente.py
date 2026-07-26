"""
L0 · Higiene del código fuente del backend  —  C4-a, A4-a, A8-b(servidor), M1, M10
(§4.2 C4-a, §4.3 A4-a/A8-b, §4.4 M1/M10 del PLAN-DE-PRUEBAS.md)

Nivel L0 (§2): los `.py` del backend se leen como **texto** y se analizan con
`ast.parse` (que NO ejecuta el módulo → seguro en el host; §2.1). Trampa 16 en
todo: nombres/llamadas se detectan por **AST** o por línea sin comentario, nunca
con `str in source` a secas —varios IDs (settings, iterations, str(e)) aparecen en
comentarios que describen precisamente lo que se retiró—.

  C4-a: 0 `print(...)` / `traceback.print_exc()` en `myapp/views/`, `models.py`,
        `encryption_utils.py`, `middleware.py` y `demo/`. Por AST: sólo cuentan las
        llamadas a `print` (nombre) y `*.print_exc`; así `create_device_fingerprint(`
        (contiene "print(") u otros `*print` NO disparan falso positivo.

  A4-a: exactamente UNA `def get_client_ip` en todo `myapp/`, y vive en
        `utils/request_utils.py`. `get_client_ip_with_trust` es otra función y NO
        cuenta. Los consumidores la IMPORTAN de `request_utils`, no la redefinen.

  A8-b (parte servidor): en el backend NO queda ningún `iterations=100000` (PBKDF2
        residual del cifrado v1, purgado en el paso 27). La parte de cliente
        (Argon2id KDF_PARAMS) es L3-vitest, no aquí.

  M1 (straggler): en los cuerpos de respuesta de `myapp/views/` sólo queda UN
        `str(e)` fugado, en general_views.py:147. El test "no hay más fugas que el
        straggler" es verde (regresión: un str(e) NUEVO lo rompe); el test "0 fugas
        totales" es xfail(strict, fase3) SOBRE el straggler: cuando la Fase 3 lo
        cierre, pasará a XPASS → rojo → "quita el xfail" (§3).

  M10: la cadena `getattr(x, "settings", ...)` NO aparece como llamada VIVA en
        `middleware.py`. Por AST: se busca un `getattr` cuyo 2º argumento sea el
        literal "settings"; que el string "settings" aparezca en rutas o comentarios
        no cuenta (trampa 16).
"""

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.l0

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BACKEND = _REPO_ROOT / "backend"
_MYAPP = _BACKEND / "myapp"

# Nombres de constructor de respuesta HTTP: un str(e) dentro de su subárbol es una
# fuga hacia el cliente.
_RESPONSE_CTORS = {
    "Response",
    "JsonResponse",
    "HttpResponse",
    "HttpResponseBadRequest",
    "HttpResponseServerError",
    "HttpResponseForbidden",
    "HttpResponseNotFound",
}

# Nombres habituales de la variable de excepción capturada.
_EXC_NAMES = {"e", "exc", "ex", "error", "err", "exception"}


# --------------------------------------------------------------------------- #
# Helpers de lectura + AST (locales; los L0 no importan Django).
# --------------------------------------------------------------------------- #
def _read(path: Path) -> str:
    assert path.is_file(), f"No se encuentra el fichero esperado: {path}"
    return path.read_text(encoding="utf-8")


def _tree(path: Path) -> ast.Module:
    return ast.parse(_read(path), filename=str(path))


def _rel(path: Path) -> str:
    return path.relative_to(_REPO_ROOT).as_posix()


def _views_files() -> list[Path]:
    return sorted((_MYAPP / "views").glob("*.py"))


def _c4_scope_files() -> list[Path]:
    """Ficheros del ámbito de C4-a: views/, models.py, encryption_utils.py,
    middleware.py y demo/."""
    files = _views_files()
    for rel in ("models.py", "encryption_utils.py", "middleware.py"):
        p = _MYAPP / rel
        if p.is_file():
            files.append(p)
    files.extend(sorted((_BACKEND / "demo").glob("*.py")))
    return files


# =====================================================================
# C4-a — sin print(...) ni traceback.print_exc() en el ámbito sensible
# =====================================================================

def _print_calls(tree: ast.Module) -> list[int]:
    """Líneas con una llamada VIVA a `print(...)` o `*.print_exc(...)`."""
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "print":
            hits.append(node.lineno)
        elif isinstance(func, ast.Attribute) and func.attr == "print_exc":
            hits.append(node.lineno)
    return hits


@pytest.mark.parametrize(
    "path", _c4_scope_files(), ids=lambda p: _rel(p)
)
def test_c4a_sin_print_ni_print_exc(path):
    """Ningún `print`/`print_exc` filtra estado a stdout/stderr en el ámbito C4-a."""
    hits = _print_calls(_tree(path))
    assert not hits, (
        f"{_rel(path)} tiene print()/print_exc() vivos en las líneas {hits}; "
        "usa el logger, no stdout (C4-a)."
    )


# =====================================================================
# A4-a — una sola def get_client_ip, en request_utils; el resto la importa
# =====================================================================

def _def_names(tree: ast.Module) -> list[str]:
    return [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def test_a4a_una_sola_definicion_de_get_client_ip():
    """
    En todo `myapp/` hay exactamente UNA `def get_client_ip` y está en
    `utils/request_utils.py`. `get_client_ip_with_trust` es otro nombre y no cuenta.
    """
    definiciones = []
    for path in sorted(_MYAPP.rglob("*.py")):
        for name in _def_names(_tree(path)):
            if name == "get_client_ip":  # exacto: excluye get_client_ip_with_trust
                definiciones.append(_rel(path))

    assert definiciones == ["backend/myapp/utils/request_utils.py"], (
        "Se esperaba una única definición de get_client_ip en "
        f"utils/request_utils.py; encontradas en: {definiciones}. Redefinirla en "
        "otro módulo reabre A4 (rate limiting evadible por X-Forwarded-For)."
    )


def test_a4a_consumidores_la_importan_de_request_utils():
    """
    Los módulos que usan `get_client_ip` (fuera de su definición) la IMPORTAN de
    `request_utils`; ninguno la redefine. Se detecta por AST: uso como llamada +
    ImportFrom con el nombre.
    """
    def_module = _MYAPP / "utils" / "request_utils.py"
    ofensivos = []
    for path in sorted(_MYAPP.rglob("*.py")):
        if path == def_module:
            continue
        tree = _tree(path)

        usa = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "get_client_ip"
            for n in ast.walk(tree)
        )
        if not usa:
            continue

        importa = any(
            isinstance(n, ast.ImportFrom)
            and n.module is not None
            and n.module.endswith("request_utils")
            and any(alias.name == "get_client_ip" for alias in n.names)
            for n in ast.walk(tree)
        )
        if not importa:
            ofensivos.append(_rel(path))

    assert not ofensivos, (
        "Estos módulos usan get_client_ip sin importarla de request_utils "
        f"(¿copia local?): {ofensivos} (A4-a)."
    )


# =====================================================================
# A8-b (servidor) — sin PBKDF2 residual (iterations=100000) en el backend
# =====================================================================

def _pbkdf2_iterations_calls(tree: ast.Module) -> list[int]:
    """Líneas con un keyword `iterations=100000` en una llamada (AST)."""
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if (
                kw.arg == "iterations"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value == 100000
            ):
                hits.append(node.lineno)
    return hits


def test_a8b_servidor_sin_pbkdf2_100000_residual():
    """
    En ningún `.py` de `myapp/` queda `iterations=100000`: el cifrado v1 del
    servidor (PBKDF2 100k → A8) se purgó en el paso 27. El KDF del cliente
    (Argon2id) se ancla en L3-vitest (Z4/A8-b), no aquí.
    """
    ofensivos = []
    for path in sorted(_MYAPP.rglob("*.py")):
        for lineno in _pbkdf2_iterations_calls(_tree(path)):
            ofensivos.append(f"{_rel(path)}:{lineno}")

    assert not ofensivos, (
        "Reaparece PBKDF2 con iterations=100000 en el servidor (residual de la "
        f"cripto v1, A8): {ofensivos}. En v2 el cifrado es del cliente (A8-b)."
    )


# =====================================================================
# M1 — str(e) en cuerpos de respuesta de myapp/views/ (straggler)
# =====================================================================

def _str_exc_leaks(tree: ast.Module) -> list[int]:
    """
    Líneas donde un `str(<exc>)` aparece dentro del subárbol de un constructor de
    respuesta HTTP (Response/JsonResponse/...). Es la forma de "fuga al cliente":
    el mensaje crudo de la excepción acaba en el cuerpo de la respuesta.
    """
    leaks = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        ctor = (
            func.id if isinstance(func, ast.Name) else
            func.attr if isinstance(func, ast.Attribute) else None
        )
        if ctor not in _RESPONSE_CTORS:
            continue
        for sub in ast.walk(node):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "str"
                and len(sub.args) == 1
                and isinstance(sub.args[0], ast.Name)
                and sub.args[0].id in _EXC_NAMES
            ):
                leaks.append(sub.lineno)
    return leaks


def _all_view_leaks() -> list[str]:
    """`fichero:linea` de cada str(e) fugado en cuerpos de respuesta de views/."""
    out = []
    for path in _views_files():
        for lineno in _str_exc_leaks(_tree(path)):
            out.append(f"{_rel(path)}:{lineno}")
    return out


# El único str(e) tolerado hoy (§1.1). Reverificado sobre el código: es
# `return JsonResponse({'success': False, 'error': str(e)}, status=400)`.
_M1_STRAGGLER = "backend/myapp/views/general_views.py:147"


def test_m1_sin_fugas_str_e_salvo_el_straggler_conocido():
    """
    Regresión: no hay NINGÚN `str(e)` en cuerpos de respuesta de views/ salvo el
    straggler conocido. Un str(e) NUEVO (en otra vista o en otra línea) rompe este
    test en el acto, aunque el straggler siga pendiente de Fase 3.
    """
    nuevos = [loc for loc in _all_view_leaks() if loc != _M1_STRAGGLER]
    assert not nuevos, (
        "Aparecen fugas NUEVAS de str(e) en cuerpos de respuesta de views/ "
        f"(aparte del straggler {_M1_STRAGGLER}): {nuevos}. No expongas el mensaje "
        "crudo de la excepción al cliente (M1)."
    )


@pytest.mark.fase3
@pytest.mark.xfail(
    strict=True,
    reason=(
        "M1 — straggler str(e) en general_views.py:147 aún expuesto al cliente; "
        "cierra en Fase 3"
    ),
)
def test_m1_straggler_str_e_eliminado():
    """
    El día que la Fase 3 elimine el straggler, `_all_view_leaks()` quedará vacío y
    este test pasará → XPASS → rojo por `xfail_strict`, avisando de que hay que
    retirar este marcador. Hoy el straggler sigue → XFAIL.
    """
    assert _all_view_leaks() == [], (
        "Todavía hay str(e) en cuerpos de respuesta de views/: "
        f"{_all_view_leaks()} (M1, straggler)."
    )


def test_m1_el_straggler_sigue_siendo_el_esperado():
    """
    Ancla el straggler: hoy existe y está exactamente en general_views.py:147. Si
    esta ubicación cambia (refactor) hay que actualizar `_M1_STRAGGLER` y el xfail.
    Si el straggler desaparece, este test falla y remite al xfail de arriba (que
    entonces será XPASS): las dos señales apuntan al mismo cierre.
    """
    assert _M1_STRAGGLER in _all_view_leaks(), (
        f"El straggler esperado {_M1_STRAGGLER} ya no está donde se documentó; "
        "reverifica M1 (¿se cerró? entonces mira el XPASS de "
        "test_m1_straggler_str_e_eliminado)."
    )


# =====================================================================
# M10 — sin getattr(x, "settings", ...) vivo en middleware.py
# =====================================================================

def test_m10_sin_getattr_settings_en_middleware():
    """
    En `middleware.py` no hay ninguna llamada VIVA `getattr(x, "settings", ...)`
    sobre un literal. Se detecta por AST (trampa 16): que el string "settings"
    aparezca en rutas (`/api/user-settings/`) o en `settings.SESSION_COOKIE_SECURE`
    (acceso por atributo, no getattr) NO cuenta.
    """
    tree = _tree(_MYAPP / "middleware.py")
    ofensivos = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "settings"
        ):
            ofensivos.append(node.lineno)

    assert not ofensivos, (
        "middleware.py vuelve a tener un getattr(x, 'settings', ...) vivo en las "
        f"líneas {ofensivos} (M10)."
    )
