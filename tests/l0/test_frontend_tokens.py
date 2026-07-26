"""
L0 · Frontend: custodia de tokens y CSPRNG del generador  —  A1-a + N2
(§4.3 A1-a y §4.5 N2 del PLAN-DE-PRUEBAS.md)

Nivel L0 (§2): ficheros de frontend leídos como **texto**; nada se ejecuta.

  A1-a: `authService.ts` NO guarda tokens (access/refresh) en localStorage ni
        sessionStorage. Antes vivían en ambos (legibles desde JS -> un XSS se
        llevaba la sesión una semana entera). OJO: el fichero SÍ usa localStorage,
        pero SÓLO para `user_data` (no secreto); por eso no vale un
        `"localStorage" not in source`, hay que mirar QUÉ se guarda.

  N2:   `passwordGenerator.ts` genera con `crypto.getRandomValues` (CSPRNG), no
        con `Math.random()`, y sus tres consumidores importan de ahí.
        ⚠️ N2 está CERRADO en el árbol (commit 26b4c97): esto es un test de
        REGRESIÓN, **no** xfail. El único `Math.random` que queda es un COMENTARIO
        que describe el `.sort(() => Math.random()-0.5)` retirado; por eso NO se usa
        `"Math.random" in source`, sino la comprobación de que no es una llamada
        VIVA (toda línea con `Math.random` es un comentario).
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.l0

_AUTH_REL = "frontend/src/services/authService.ts"
_GEN_REL = "frontend/src/services/passwordGenerator.ts"
_CONSUMERS_REL = [
    "frontend/src/pages/PasswordGeneratorPage.tsx",
    "frontend/src/components/account/AddPasswordModal.tsx",
    "frontend/src/components/account/EditPasswordModal.tsx",
]

# --- Helpers de "llamada viva" -------------------------------------------------
# Sin AST de TypeScript en el host: se trabaja línea a línea y se considera que
# una aparición es un COMENTARIO si el `//` de la línea precede al patrón. Es la
# forma L0 de distinguir código vivo de una nota (§ nota de N2 en el prompt).

def _live_lines_with(source: str, needle: str) -> list[str]:
    """Devuelve las líneas donde `needle` aparece como código, no en un `//`."""
    live = []
    for line in source.splitlines():
        pos = line.find(needle)
        if pos == -1:
            continue
        comment = line.find("//")
        if comment == -1 or comment > pos:
            live.append(line)
    return live


# =====================================================================
# A1-a — ningún token en localStorage / sessionStorage
# =====================================================================

@pytest.fixture(scope="module")
def auth_src(read_repo_text) -> str:
    return read_repo_text(_AUTH_REL)


# Captura los argumentos de cada `localStorage.setItem(...)` / `sessionStorage.setItem(...)`.
_SETITEM_RE = re.compile(
    r"(?:localStorage|sessionStorage)\.setItem\s*\(([^)]*)", re.MULTILINE
)
_TOKENISH_RE = re.compile(r"access|refresh|token", re.IGNORECASE)


def test_a1a_ningun_setitem_guarda_un_token(auth_src):
    """
    Se recorre cada `setItem(...)` y se afirma que sus argumentos no mencionan
    access/refresh/token. Lo único que authService persiste es `this.userKey`
    ('user_data'), que no es secreto.
    """
    setitems = _SETITEM_RE.findall(auth_src)
    assert setitems, (
        "No se encontró ningún setItem en authService.ts; el test asume que "
        "existe al menos el de user_data. ¿Cambió el fichero? (A1-a)"
    )
    ofensivos = [args for args in setitems if _TOKENISH_RE.search(args)]
    assert not ofensivos, (
        "authService.ts guarda algo con pinta de token en storage "
        f"(access/refresh/token): {ofensivos!r}. Los tokens deben vivir SÓLO en "
        "cookies HttpOnly (A1-a)."
    )


def test_a1a_get_access_token_devuelve_null(auth_src):
    """
    `getAccessToken()` devuelve `null`: con cookies HttpOnly no hay token legible
    desde JS. Regresión de que no se reintroduce una lectura de token desde storage.
    """
    assert re.search(
        r"getAccessToken\s*\([^)]*\)[^{]*\{\s*return null;\s*\}", auth_src
    ), (
        "getAccessToken ya no devuelve `return null;`: ¿se ha reintroducido un "
        "token accesible desde JS? (A1-a)"
    )


def test_a1a_sin_authorization_bearer_desde_storage(auth_src):
    """
    No se arma una cabecera `Authorization` con un token sacado de storage: el
    access viaja en la cookie HttpOnly que el navegador adjunta solo.
    """
    for m in re.finditer(r"['\"]Authorization['\"]", auth_src):
        line = auth_src[: m.start()].count("\n")
        source_line = auth_src.splitlines()[line]
        # Sólo saltaría si Authorization apareciese como asignación viva; hoy no
        # aparece en absoluto. Si reaparece, que sea con un comentario explícito.
        comment = source_line.find("//")
        assert comment != -1 and comment < source_line.find("Authorization"), (
            "authService.ts vuelve a construir una cabecera Authorization; con "
            "cookies HttpOnly no debería (A1-a)."
        )


# =====================================================================
# N2 — CSPRNG en el generador (regresión; NO xfail: cerrado en 26b4c97)
# =====================================================================

@pytest.fixture(scope="module")
def gen_src(read_repo_text) -> str:
    return read_repo_text(_GEN_REL)


def test_n2_generador_usa_csprng(gen_src):
    assert "crypto.getRandomValues" in gen_src, (
        "passwordGenerator.ts no usa crypto.getRandomValues (CSPRNG) (N2)."
    )


def test_n2_generador_sin_math_random_vivo(gen_src):
    """
    El único `Math.random` permitido es el del COMENTARIO que describe el
    `.sort(() => Math.random()-0.5)` retirado. Ninguna llamada viva.
    """
    vivos = _live_lines_with(gen_src, "Math.random")
    assert not vivos, (
        "passwordGenerator.ts tiene una llamada VIVA a Math.random (no CSPRNG): "
        f"{vivos!r} (N2)."
    )


@pytest.mark.parametrize("rel", _CONSUMERS_REL, ids=[Path(r).name for r in _CONSUMERS_REL])
def test_n2_consumidor_importa_del_generador(rel, read_repo_text):
    """Los tres consumidores importan el CSPRNG de `services/passwordGenerator`."""
    src = read_repo_text(rel)
    assert re.search(
        r"""import\s*\{[^}]*\}\s*from\s*['"][^'"]*services/passwordGenerator['"]""",
        src,
    ), f"{Path(rel).name} no importa de 'services/passwordGenerator' (N2)."


@pytest.mark.parametrize("rel", _CONSUMERS_REL, ids=[Path(r).name for r in _CONSUMERS_REL])
def test_n2_consumidor_sin_math_random_vivo(rel, read_repo_text):
    """Ningún consumidor genera con Math.random (usan el CSPRNG importado)."""
    src = read_repo_text(rel)
    vivos = _live_lines_with(src, "Math.random")
    assert not vivos, (
        f"{Path(rel).name} tiene una llamada VIVA a Math.random: {vivos!r} (N2)."
    )
