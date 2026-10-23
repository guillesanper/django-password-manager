"""
L0 · Imagen de `web`  —  N11 (§4.5 del PLAN-DE-PRUEBAS.md)

Todo se lee como texto; ni se construye la imagen ni se importa Django.

  N11  `COPY . .` metía en la imagen de `web` el `.env` con todos los secretos y la clave
       privada de nginx: el `.dockerignore` estaba en la raíz del repo y el contexto de
       build es `backend/`, así que Docker no lo leía. Se comprueba sobre el contexto que
       declara el compose, con las reglas de coincidencia de Docker, qué rutas quedan dentro
       y cuáles fuera.
       Además, toda imagen (FROM, COPY --from e `image:`) va fijada por digest, la imagen
       final de `web` no lleva compilador y la aplicación no corre como root: el entrypoint
       baja a `app` tras preparar los logs.
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


# --------------------------------------------------------------------------- #
# Imágenes fijadas por digest, sin compilador y sin root
# --------------------------------------------------------------------------- #
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")

# Imágenes que se aceptan sin digest, con el motivo.
_SIN_DIGEST = {
    # Ya no está en Docker Hub: no se puede resolver su digest desde el repo (N11).
    "minio/minio:RELEASE.2024-08-17T01-24-54Z",
}


@pytest.fixture(scope="module")
def servicios(read_repo_text):
    return yaml.safe_load(read_repo_text(_COMPOSE_REL))["services"]


def _instrucciones(texto):
    """Instrucciones de un Dockerfile, con las continuaciones de línea unidas."""
    texto = re.sub(r"\\\n", " ", texto)
    lineas = (linea.strip() for linea in texto.splitlines())
    return [linea for linea in lineas if linea and not linea.startswith("#")]


def _etapas(texto):
    """Lista de etapas: cada una es la lista de sus instrucciones, empezando por el FROM."""
    etapas = []
    for instruccion in _instrucciones(texto):
        if instruccion.upper().startswith("FROM "):
            etapas.append([])
        if etapas:
            etapas[-1].append(instruccion)
    return etapas


@pytest.fixture(scope="module")
def dockerfiles(servicios, read_repo_text):
    """Ruta -> texto de cada Dockerfile que construye el compose."""
    base = PurePosixPath(_COMPOSE_REL).parent
    rutas = []
    for servicio in servicios.values():
        build = servicio.get("build")
        if build is None:
            continue
        contexto = build if isinstance(build, str) else build.get("context", ".")
        dockerfile = "Dockerfile" if isinstance(build, str) else build.get("dockerfile", "Dockerfile")
        rutas.append(str(base / contexto / dockerfile).replace("/./", "/"))
    return {ruta: read_repo_text(ruta) for ruta in rutas}


def _referencias(texto):
    """Imágenes externas que usa un Dockerfile (FROM y COPY --from), sin las etapas propias."""
    alias, referencias = set(), []
    for instruccion in _instrucciones(texto):
        partes = instruccion.split()
        if partes[0].upper() == "FROM":
            referencias.append(partes[1])
            if len(partes) >= 4 and partes[2].upper() == "AS":
                alias.add(partes[3])
        elif partes[0].upper() == "COPY":
            origen = next((p.split("=", 1)[1] for p in partes if p.startswith("--from=")), None)
            if origen:
                referencias.append(origen)
    return [r for r in referencias if r not in alias]


def test_n11_las_imagenes_del_compose_van_por_digest(servicios):
    sueltas = [
        f"{nombre}: {s['image']}"
        for nombre, s in servicios.items()
        if "image" in s and s["image"] not in _SIN_DIGEST and not _DIGEST.search(s["image"])
    ]
    assert not sueltas, f"imágenes sin digest en el compose: {sueltas}"


def test_n11_las_imagenes_de_los_dockerfile_van_por_digest(dockerfiles):
    sueltas = [
        f"{ruta}: {ref}"
        for ruta, texto in dockerfiles.items()
        for ref in _referencias(texto)
        if not _DIGEST.search(ref)
    ]
    assert not sueltas, f"imágenes sin digest en los Dockerfile: {sueltas}"


# Opciones de `pip install` que llevan un valor detrás: ese valor no es un paquete. Un
# requirements.txt se acepta: sus versiones las vigila M5.
_OPCIONES_CON_VALOR = {"-r", "--requirement", "-c", "--constraint", "--python", "-p"}


def _paquetes_de_pip(instruccion):
    argumentos = instruccion.split("pip install", 1)[1].split("&&", 1)[0].split()
    paquetes, saltar = [], False
    for argumento in argumentos:
        if saltar:
            saltar = False
        elif argumento in _OPCIONES_CON_VALOR:
            saltar = True
        elif not argumento.startswith("-"):
            paquetes.append(argumento)
    return paquetes


def test_n11_pip_instala_versiones_exactas(dockerfiles):
    sueltos = [
        f"{ruta}: {paquete}"
        for ruta, texto in dockerfiles.items()
        for instruccion in _instrucciones(texto)
        if "pip install" in instruccion
        for paquete in _paquetes_de_pip(instruccion)
        if "==" not in paquete
    ]
    assert not sueltos, f"paquetes sin versión exacta: {sueltos}"


def test_n11_la_imagen_final_de_web_no_lleva_compilador(read_repo_text):
    final = " ".join(_etapas(read_repo_text("backend/Dockerfile"))[-1])
    for herramienta in ("build-essential", "gcc", "g++"):
        assert herramienta not in final, f"la imagen final de `web` instala {herramienta}"


def test_n11_web_no_corre_como_root(read_repo_text):
    final = _etapas(read_repo_text("backend/Dockerfile"))[-1]
    assert 'ENTRYPOINT ["docker-entrypoint.sh"]' in final, "web no arranca por el entrypoint"
    entrypoint = read_repo_text("backend/docker-entrypoint.sh")
    assert "exec setpriv --reuid=app --regid=app" in entrypoint, (
        "el entrypoint no baja a `app` antes de ejecutar la aplicación"
    )
