"""
Infraestructura COMPARTIDA de los tests de host (L0 y, más adelante, L2).

Sólo helpers de lectura de ficheros del repo como **texto** y parseo **AST** de
`settings.py`. Nada aquí importa Django ni levanta la pila: los L0 se mantienen a
nivel de texto/AST (§2.1 del PLAN-DE-PRUEBAS.md).

`tests/l0/test_config_django.py` (tanda 1) trae su propia copia de estos helpers a
propósito —no se refactoriza— para que fuera autocontenido. A partir de la tanda 2
los nuevos L0 consumen estas fixtures.

Rutas reales del repo (la maqueta del andamiaje era esquemática):
  - settings:  backend/demo/settings.py
  - compose:   backend/docker-compose.yml         (+ docker-compose.override.yml)
  - nginx:     backend/infrastructure/nginx/nginx.conf
"""

import ast
from pathlib import Path

import pytest


# --------------------------------------------------------------------------- #
# Localización robusta de la raíz del repo.
# --------------------------------------------------------------------------- #
# No dependemos sólo de `parents[N]`: subimos desde este fichero hasta la primera
# carpeta que contenga a la vez AUDITORIA-SEGURIDAD.md y backend/. Así el mismo
# conftest funciona aunque se mueva de sitio o se ejecute pytest desde otro cwd.
def _find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "AUDITORIA-SEGURIDAD.md").is_file() and (
            candidate / "backend"
        ).is_dir():
            return candidate
    # Fallback: tests/ cuelga de la raíz -> parents[1].
    return start.parents[1]


_REPO_ROOT = _find_repo_root(Path(__file__).resolve())


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Raíz del repositorio (contiene AUDITORIA-SEGURIDAD.md y backend/)."""
    return _REPO_ROOT


@pytest.fixture(scope="session")
def repo_path(repo_root):
    """Devuelve un callable rel -> Path absoluta bajo la raíz del repo."""

    def _resolve(relative: str) -> Path:
        return repo_root / relative

    return _resolve


@pytest.fixture(scope="session")
def read_repo_text(repo_root):
    """
    Callable rel -> str: lee un fichero del repo como texto UTF-8. Falla claro si
    no existe (mejor que un FileNotFoundError críptico a mitad de aserción).
    """

    def _read(relative: str) -> str:
        path = repo_root / relative
        if not path.is_file():
            raise AssertionError(f"No se encuentra el fichero esperado: {path}")
        return path.read_text(encoding="utf-8")

    return _read


# --------------------------------------------------------------------------- #
# Parseo AST de settings.py (extraído de la tanda 1 para reuso en próximas tandas).
# --------------------------------------------------------------------------- #
_SETTINGS_REL = "backend/demo/settings.py"


def _top_level_assignments(tree: ast.Module):
    """
    Recorre SÓLO el cuerpo del módulo (no entra en `if DEBUG:` ni en funciones):

      - names:    conjunto de nombres asignados a nivel de módulo.
      - literals: nombre -> valor, para las asignaciones cuyo lado derecho es un
                  literal evaluable (str, bool, tupla, lista...). Las asignaciones
                  con llamadas (`os.getenv(...)`, `_env_bool(...)`) no entran aquí.

    Al mirar sólo el nivel de módulo, un `CSP_SCRIPT_SRC` reasignado dentro de
    `if DEBUG:` NO pisa el valor de producción: se captura el de producción.
    """
    names = set()
    literals = {}
    for node in tree.body:
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


@pytest.fixture(scope="session")
def settings_source(read_repo_text) -> str:
    """Texto crudo de backend/demo/settings.py (para aserciones por regex)."""
    return read_repo_text(_SETTINGS_REL)


@pytest.fixture(scope="session")
def settings_tree(settings_source) -> ast.Module:
    """AST de settings.py. `ast.parse` NO ejecuta el módulo: seguro en el host."""
    return ast.parse(settings_source, filename=_SETTINGS_REL)


@pytest.fixture(scope="session")
def settings_assignments(settings_tree):
    """(names, literals) de las asignaciones de nivel de módulo de settings.py."""
    return _top_level_assignments(settings_tree)
