"""
L0 · Dependencias fijadas, sin muertas y sin CVE conocidas  —  M5, N16
(§4.4 M5 del PLAN-DE-PRUEBAS.md, §7·decies N16 de AUDITORIA-SEGURIDAD.md)

`backend/requirements.in` lleva las dependencias directas y `backend/requirements.txt` se
genera desde él con `uv pip compile --generate-hashes`: todas las transitivas fijadas y con
hash, que el Dockerfile exige (`--require-hashes`).

Antes este test tenía umbrales FIJOS para cuatro paquetes, elegidos en 2024 y marcados xfail.
Se quedaron cortos: pip-audit encontraba siete paquetes con avisos, gunicorn y DRF entre
ellos, y Django 5.1.5 ya no bastaba (la serie 5.1 está sin soporte). Ahora:

  - Sin red (L0 de verdad): `requirements.txt` fijado entero con hashes, igual que el `.in`,
    sin las dependencias muertas y por encima de las versiones que corrigen los avisos que
    había al cerrar N16. Esto último es una red mínima, no la lista de CVE.
  - Con red (`red`): `pip-audit` contra la base de vulnerabilidades de PyPI. Es la
    comprobación que sigue valiendo cuando aparezcan avisos nuevos. Se salta si `pip-audit`
    no está instalado; sin red, se deselecciona con `-m "not red"`.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.l0

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REQUIREMENTS_IN = _REPO_ROOT / "backend/requirements.in"
_REQUIREMENTS_TXT = _REPO_ROOT / "backend/requirements.txt"

# Versión que corrige los avisos de pip-audit (base de PyPI) sobre lo que había fijado antes
# de N16. Una dependencia que baje de aquí vuelve a tener una vulnerabilidad conocida.
_MINIMOS = {
    "django": "5.2.17",
    "gunicorn": "23.0.0",  # request smuggling detrás de nginx (CVE-2024-6827)
    "djangorestframework": "3.18.2",
    "cryptography": "49.0.0",
    "requests": "2.33.0",
    "urllib3": "2.8.0",
}

# Ningún código las importaba ni las configuraba (N16, AU-15). `ipaddress` es el backport de
# Python 2: el `import ipaddress` del código es el de la biblioteca estándar.
_MUERTAS = (
    "celery", "flower", "sentry-sdk", "django-debug-toolbar", "django-extensions",
    "boto3", "netaddr", "ipaddress", "python-dateutil",
)

_PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)(\[[^\]]*\])?==([0-9][0-9A-Za-z.+!-]*)")


def _nombre(nombre: str) -> str:
    """Nombre normalizado (PEP 503): minúsculas y `-` en lugar de `_` y `.`."""
    return re.sub(r"[-_.]+", "-", nombre).lower()


def _requisitos(texto: str) -> list[str]:
    """Una cadena por requisito, con las continuaciones (`\\`) unidas y sin comentarios."""
    logicas, actual = [], ""
    for linea in texto.splitlines():
        linea = linea.split(" #", 1)[0].rstrip() if not linea.lstrip().startswith("#") else ""
        if linea.endswith("\\"):
            actual += linea[:-1] + " "
            continue
        actual += linea
        if actual.strip():
            logicas.append(actual.strip())
        actual = ""
    return logicas


def _pins(texto: str) -> dict[str, str]:
    pins = {}
    for req in _requisitos(texto):
        m = _PIN_RE.match(req)
        if m:
            pins[_nombre(m.group(1))] = m.group(3)
    return pins


def _version(version: str) -> tuple[int, ...]:
    return tuple(int(re.match(r"\d+", s).group()) if re.match(r"\d+", s) else 0
                 for s in version.split("."))


def _ge(a: str, b: str) -> bool:
    ta, tb = _version(a), _version(b)
    ancho = max(len(ta), len(tb))
    return ta + (0,) * (ancho - len(ta)) >= tb + (0,) * (ancho - len(tb))


_TXT = _REQUIREMENTS_TXT.read_text(encoding="utf-8")
_IN = _REQUIREMENTS_IN.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Sin red
# --------------------------------------------------------------------------- #
def test_m5_requirements_fijado_entero_con_hashes():
    sueltos = [
        req.split()[0] for req in _requisitos(_TXT)
        if not _PIN_RE.match(req) or "--hash=sha256:" not in req
    ]
    assert not sueltos, (
        f"requisitos sin `==` o sin hash en requirements.txt: {sueltos}. Regenera con "
        "`uv pip compile requirements.in --generate-hashes ...` (ver requirements.in)."
    )


def test_m5_directas_fijadas_igual_en_el_in_y_en_el_txt():
    directas, fijadas = _pins(_IN), _pins(_TXT)
    assert directas, "requirements.in no fija ninguna dependencia con =="
    distintas = {
        nombre: (version, fijadas.get(nombre))
        for nombre, version in directas.items()
        if fijadas.get(nombre) != version
    }
    assert not distintas, (
        f"requirements.txt no está generado desde el requirements.in actual: {distintas}"
    )


@pytest.mark.parametrize("nombre, minimo", sorted(_MINIMOS.items()))
def test_m5_dependencia_por_encima_de_su_correccion(nombre, minimo):
    fijada = _pins(_TXT).get(nombre)
    assert fijada is not None, f"{nombre} ya no está en requirements.txt"
    assert _ge(fijada, minimo), (
        f"{nombre}=={fijada} está por debajo de {minimo}, la versión que corrige sus avisos "
        "conocidos (M5)."
    )


@pytest.mark.parametrize("nombre", _MUERTAS)
def test_n16_dependencia_muerta_no_vuelve(nombre):
    assert nombre not in _pins(_IN) and nombre not in _pins(_TXT), (
        f"{nombre} vuelve a requirements y ningún código la usa: superficie y avisos de "
        "seguridad sin ningún beneficio."
    )


# --------------------------------------------------------------------------- #
# Con red
# --------------------------------------------------------------------------- #
@pytest.mark.red
def test_m5_pip_audit_sin_avisos():
    pip_audit = shutil.which("pip-audit")
    if pip_audit is None:
        pytest.skip("pip-audit no está instalado (pip install pip-audit)")
    resultado = subprocess.run(
        [pip_audit, "-r", str(_REQUIREMENTS_TXT), "--vulnerability-service", "pypi",
         "--disable-pip", "--require-hashes", "--progress-spinner", "off"],
        capture_output=True, text=True, timeout=600, check=False,
    )
    assert resultado.returncode == 0, (
        "pip-audit encuentra avisos (o no pudo consultar PyPI):\n"
        f"{resultado.stdout}\n{resultado.stderr}"
    )
