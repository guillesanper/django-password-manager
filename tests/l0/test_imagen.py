"""
L0 · Imagen de `web`  —  N11 (§4.5 del PLAN-DE-PRUEBAS.md)

Todo se lee como texto; ni se construye la imagen ni se importa Django.

  N11  `COPY . .` metía en la imagen de `web` el `.env` con todos los secretos y la clave
       privada de nginx: el `.dockerignore` estaba en la raíz del repo y el contexto de
       build es `backend/`, así que Docker no lo leía. Se comprueba sobre el contexto que
       declara el compose, con las reglas de coincidencia de Docker, qué rutas quedan dentro
       y cuáles fuera.
"""

import re
from pathlib import PurePosixPath

import pytest
import yaml

pytestmark = pytest.mark.l0

_COMPOSE_REL = "backend/docker-compose.yml"


# --------------------------------------------------------------------------- #
# Reglas de .dockerignore con la semántica de Docker (moby/patternmatcher)
# --------------------------------------------------------------------------- #
def _a_regex(patron):
    """`*` y `?` no cruzan `/`; `**` sí, cualquier número de directorios."""
    regex, i = "", 0
    while i < len(patron):
        if patron.startswith("**/", i):
            regex, i = regex + "(?:.*/)?", i + 3
        elif patron.startswith("**", i):
            regex, i = regex + ".*", i + 2
        elif patron[i] == "*":
            regex, i = regex + "[^/]*", i + 1
        elif patron[i] == "?":
            regex, i = regex + "[^/]", i + 1
        else:
            regex, i = regex + re.escape(patron[i]), i + 1
    return re.compile(regex)


def _reglas(texto):
    reglas = []
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        excepcion = linea.startswith("!")
        patron = linea.lstrip("!").strip().strip("/")
        reglas.append((excepcion, _a_regex(patron)))
    return reglas


def _ignorada(ruta, reglas):
    """Como Docker: una regla casa con la ruta o con un directorio padre; manda la última."""
    partes = PurePosixPath(ruta).parts
    candidatas = ["/".join(partes[: n + 1]) for n in range(len(partes))]
    ignorada = False
    for excepcion, regex in reglas:
        if any(regex.fullmatch(c) for c in candidatas):
            ignorada = not excepcion
    return ignorada


@pytest.fixture(scope="module")
def contexto_web(read_repo_text):
    """Directorio del contexto de build de `web`, relativo a la raíz del repo."""
    build = yaml.safe_load(read_repo_text(_COMPOSE_REL))["services"]["web"]["build"]
    contexto = build if isinstance(build, str) else build.get("context", ".")
    return str(PurePosixPath(_COMPOSE_REL).parent / contexto)


@pytest.fixture(scope="module")
def reglas_web(contexto_web, repo_path):
    # Sin .dockerignore en el contexto, Docker no excluye nada.
    fichero = repo_path(f"{contexto_web}/.dockerignore")
    return _reglas(fichero.read_text(encoding="utf-8")) if fichero.is_file() else []


@pytest.mark.parametrize(
    "ruta",
    [
        ".env",
        ".env.production",
        ".env.example",
        "infrastructure/nginx/ssl/privkey.pem",
        "infrastructure/nginx/ssl/fullchain.pem",
        "infrastructure/logs/django/security.log",
        "myapp/__pycache__/views.cpython-312.pyc",
        ".coverage",
    ],
)
def test_n11_la_imagen_de_web_no_lleva_secretos_ni_artefactos(ruta, reglas_web):
    assert _ignorada(ruta, reglas_web), f"`{ruta}` entra en la imagen de `web` (COPY . .)"


@pytest.mark.parametrize(
    "ruta",
    [
        "manage.py",
        "requirements.txt",
        "demo/settings.py",
        "myapp/views/auth_views.py",
        "myapp/tests/conftest.py",  # L1 corre dentro de `web`
        "static/dist/index.html",  # build de Vite: sin él no se sirve la SPA
        "infrastructure/monitoring/check_dashboard_metrics.py",  # se lanza con exec web
    ],
)
def test_n11_la_imagen_de_web_conserva_lo_que_necesita(ruta, reglas_web):
    assert not _ignorada(ruta, reglas_web), f"`{ruta}` queda fuera de la imagen de `web`"
