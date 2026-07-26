"""
L0 · Dependencias con CVE por parchear  —  M5  (xfail ESTRICTO, deuda de Fase 3)
(§4.4 M5 del PLAN-DE-PRUEBAS.md)

Nivel L0 (§2): `backend/requirements.txt` se lee como **texto**; nada importa
Django ni ejecuta `pip`. NO se usa `pip-audit` (necesitaría red y el entorno
instalado): el umbral es **FIJO** por dependencia, elegido por encima de la última
versión con CVE conocida sin parchear, y se compara contra el pin (`==`) del
fichero.

M5 sigue **ABIERTO** (§1.1): las cuatro dependencias que la auditoría marca están
hoy por debajo de su umbral parcheado, así que cada sub-test sale **XFAIL**
(estricto, marcador `fase3`). El día que la Fase 3 suba una de ellas por encima de
su umbral, su sub-test dejará de fallar → **XPASS** → rojo por `xfail_strict`, que
es la señal de "sube el umbral / quita el xfail de esta dep" (§3).

Umbrales parcheados fijados (mínimo que consideramos sin CVE abierta conocida):

  - cryptography ≥ 42.0.4   (CVE-2023-50782, CVE-2024-0727, CVE-2024-26130)
  - Django       ≥ 5.1.5    (parches de seguridad de la serie 5.1)
  - requests     ≥ 2.32.0   (CVE-2024-35195, verificación de certificado)
  - urllib3      ≥ 2.2.2    (CVE-2024-37891, fuga de cabeceras Proxy-Authorization)

Estado real hoy (verificado en requirements.txt): 41.0.7 / 5.1 / 2.31.0 / 2.0.7.
Las cuatro por debajo → cuatro XFAIL. Ninguna está parcheada todavía; si alguna lo
estuviese, su parámetro NO llevaría el marcador xfail (ver `_build_params`).
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.l0

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REQUIREMENTS_REL = "backend/requirements.txt"

# Umbral parcheado FIJO por dependencia. La clave es el nombre tal y como aparece
# en el pin del requirements (case-insensitive al comparar).
_THRESHOLDS = {
    "cryptography": "42.0.4",
    "Django": "5.1.5",
    "requests": "2.32.0",
    "urllib3": "2.2.2",
}


# --------------------------------------------------------------------------- #
# Parseo de requirements.txt y comparación de versiones (PEP440-lite).
# --------------------------------------------------------------------------- #
# A nivel de módulo para poder decidir en tiempo de COLECCIÓN qué parámetros van
# marcados xfail (una dep ya parcheada no debe ir xfail; si va y pasa, xfail_strict
# la pondría roja, que es justo lo que no queremos para una dep correcta).

_PIN_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][0-9A-Za-z.+!-]*)")


def _parse_pins(text: str) -> dict[str, str]:
    """`nombre` (minúsculas) -> versión, para cada línea `nombre==version`."""
    pins: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _PIN_RE.match(stripped)
        if m:
            pins[m.group(1).lower()] = m.group(2)
    return pins


def _release_tuple(version: str) -> tuple[int, ...]:
    """Segmentos numéricos de release (`41.0.7` -> (41, 0, 7)).

    Sólo estas dependencias usan versiones numéricas planas; se ignora cualquier
    sufijo pre/post (`rc1`, `.post0`) quedándose con los dígitos iniciales de cada
    segmento, que basta para comparar contra el umbral.
    """
    parts = []
    for seg in version.split("."):
        digits = re.match(r"\d+", seg)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def _version_ge(a: str, b: str) -> bool:
    """¿`a` >= `b`? Con relleno de ceros para longitudes distintas (5.1 vs 5.1.5)."""
    ta, tb = _release_tuple(a), _release_tuple(b)
    width = max(len(ta), len(tb))
    ta += (0,) * (width - len(ta))
    tb += (0,) * (width - len(tb))
    return ta >= tb


_REQUIREMENTS_PATH = _REPO_ROOT / _REQUIREMENTS_REL
_PINS = _parse_pins(
    _REQUIREMENTS_PATH.read_text(encoding="utf-8")
    if _REQUIREMENTS_PATH.is_file()
    else ""
)


def _build_params():
    """Un parámetro por dependencia vigilada.

    Si el pin está por DEBAJO del umbral parcheado -> el sub-test debe fallar hoy:
    lleva `xfail(strict)` + `fase3`. Si ya está parcheado -> sin marcas: se espera
    verde y, si retrocede por debajo del umbral, fallará en rojo de inmediato.
    """
    params = []
    for name, threshold in _THRESHOLDS.items():
        pinned = _PINS.get(name.lower())
        below = pinned is not None and not _version_ge(pinned, threshold)
        marks = []
        if below:
            marks = [
                pytest.mark.xfail(
                    strict=True,
                    reason=(
                        f"M5 — {name} {pinned} < {threshold} parcheado; "
                        "cierra en Fase 3"
                    ),
                ),
                pytest.mark.fase3,
            ]
        params.append(pytest.param(name, threshold, marks=marks, id=name))
    return params


@pytest.mark.parametrize("name, threshold", _build_params())
def test_m5_dependencia_por_encima_del_umbral_parcheado(name, threshold):
    """
    El pin de `name` en requirements.txt está en el umbral parcheado o por encima.

    Hoy las cuatro salen XFAIL (M5 abierto). Cuando la Fase 3 suba una, su XPASS
    (por `xfail_strict`) obliga a retirar su marca aquí.
    """
    pinned = _PINS.get(name.lower())
    assert pinned is not None, (
        f"{name} ya no está pineada en {_REQUIREMENTS_REL}; el umbral M5 no puede "
        "verificarse. ¿Cambió el nombre o se soltó el pin?"
    )
    assert _version_ge(pinned, threshold), (
        f"M5 — {name}=={pinned} está por debajo del umbral parcheado {threshold}; "
        "dependencia con CVE conocida sin actualizar (cierra en Fase 3)."
    )
