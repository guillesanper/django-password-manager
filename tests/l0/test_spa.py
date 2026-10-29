"""
L0 · SPA / integración Vite-Django  —  T1 (vite/base/api) + A2-d
(§4.5 T1 y §4.2 A2-d del PLAN-DE-PRUEBAS.md)

Nivel L0 (§2): se leen ficheros como **texto**; nada importa Django ni Node ni
levanta la pila. Cubre la parte de T1 que NO vive en settings.py (esa —sin
`DJANGO_VITE_ASSETS_PATH` asignado, con `DJANGO_VITE_MANIFEST_PATH`— la comprueba
`test_config_django.py`, tanda 1, por AST):

  T1 (vite):   backend/static/dist como outDir y `manifest: 'manifest.json'`.
  T1 (base):   base.html carga la SPA por su entry real `src/main.tsx`.
  T1 (api):    los servicios de frontend/src/services importan `API_BASE_URL`
               del origen único (config/api.ts) y NINGUNO codifica a mano
               `http://localhost:8000` (el bug de las 8 copias que cerró T1).
  A2-d:        el <script> inline de `window.DjangoData` en base.html lleva
               `nonce="{{ request.csp_nonce }}"`; sin él, la CSP (`script-src
               'self'` sin `unsafe-inline`) bloquearía el bloque y rompería la SPA.

Trampa 16 (variante): `vite.config.ts` menciona `DJANGO_VITE_ASSETS_PATH` en un
COMENTARIO. Aquí no se comprueba ese nombre; se comprueban las claves realmente
asignadas del objeto de build (`outDir`, `manifest`), que sí son directivas vivas.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.l0

# Raíz del repo: tests/l0/ -> parents[2]. Se usa a nivel de módulo para poder
# parametrizar la lista de servicios en tiempo de colección.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SERVICES_DIR = _REPO_ROOT / "frontend" / "src" / "services"

_VITE_REL = "frontend/vite.config.ts"
_BASE_HTML_REL = "backend/myapp/templates/base.html"
_API_CONFIG_REL = "frontend/src/config/api.ts"

# Servicios que consumen la API por HTTP (excluye el núcleo cripto local
# crypto.ts / cryptoSession.ts / passwordGenerator.ts, que no hablan con el
# servidor). Se descubren dinámicamente: un servicio nuevo entra solo.
_API_SERVICES = sorted(
    p
    for p in _SERVICES_DIR.glob("*.ts")
    if "API_BASE_URL" in p.read_text(encoding="utf-8")
)


# =====================================================================
# T1 (vite) — outDir dentro de backend/ y manifest con nombre explícito
# =====================================================================

@pytest.fixture(scope="module")
def vite_src(read_repo_text) -> str:
    return read_repo_text(_VITE_REL)


def test_t1_vite_outdir_backend_static_dist(vite_src):
    """
    El build debe caer en `../backend/static/dist`: dentro del contexto de build
    de Docker (backend/) y donde django-vite/collectstatic lo buscan. Con
    `../static/dist` los assets caían en la raíz del repo y no llegaban a la imagen.
    """
    assert re.search(
        r"""outDir\s*:\s*['"]\.\./backend/static/dist['"]""", vite_src
    ), "vite.config.ts no fija outDir='../backend/static/dist' (T1)."


def test_t1_vite_manifest_nombre_explicito(vite_src):
    """
    `manifest: 'manifest.json'`, no `true`: con `true` Vite 5+ escribe
    `.vite/manifest.json` y collectstatic ignora por defecto todo lo que empieza
    por punto, así que el manifest nunca llegaría a STATIC_ROOT (T1).
    """
    assert re.search(
        r"""manifest\s*:\s*['"]manifest\.json['"]""", vite_src
    ), "vite.config.ts no fija manifest='manifest.json' (T1)."


def test_t1_vite_entry_main_tsx(vite_src):
    """El entry de rollup es `./src/main.tsx`, el mismo que carga base.html."""
    assert re.search(
        r"""main\s*:\s*['"]\./src/main\.tsx['"]""", vite_src
    ), "vite.config.ts no declara el entry main -> './src/main.tsx' (T1)."


# =====================================================================
# T1 (base) — base.html carga la SPA por su entry real src/main.tsx
# =====================================================================

@pytest.fixture(scope="module")
def base_html(read_repo_text) -> str:
    return read_repo_text(_BASE_HTML_REL)


def test_t1_base_html_carga_main_tsx(base_html):
    """
    base.html usa `{% vite_asset 'src/main.tsx' %}`. La clave del manifest es la
    ruta del origen relativa a la raíz de Vite, no el nombre del fichero.
    """
    assert re.search(
        r"""vite_asset\s+['"]src/main\.tsx['"]""", base_html
    ), "base.html no carga la SPA con {% vite_asset 'src/main.tsx' %} (T1)."


# =====================================================================
# T1 (api) — origen único de API_BASE_URL; ningún localhost:8000 a mano
# =====================================================================

def test_t1_config_api_exporta_base_url(read_repo_text):
    """config/api.ts es el origen único: exporta `API_BASE_URL`."""
    api_src = read_repo_text(_API_CONFIG_REL)
    assert re.search(
        r"export\s+const\s+API_BASE_URL\b", api_src
    ), "config/api.ts no exporta `export const API_BASE_URL` (T1)."


def test_t1_hay_varios_servicios_que_importan_api_base_url():
    """Red de seguridad: el descubrimiento no está vacío ni casi vacío."""
    assert len(_API_SERVICES) >= 9, (
        f"Se esperaban >=9 servicios importando API_BASE_URL; encontrados "
        f"{len(_API_SERVICES)} en {_SERVICES_DIR}. ¿Cambió la estructura? (T1)"
    )


@pytest.mark.parametrize(
    "service_path", _API_SERVICES, ids=[p.name for p in _API_SERVICES]
)
def test_t1_servicio_importa_api_base_url_del_origen_unico(service_path):
    """
    Cada servicio que usa API_BASE_URL lo IMPORTA de config/api (no lo redefine),
    manteniendo la fuente única. `authService.ts` guarda además `../config/api`.
    """
    src = service_path.read_text(encoding="utf-8")
    assert re.search(
        r"""import\s*\{[^}]*\bAPI_BASE_URL\b[^}]*\}\s*from\s*['"][^'"]*config/api['"]""",
        src,
    ), (
        f"{service_path.name} usa API_BASE_URL sin importarlo de "
        f"'.../config/api' (rompe la fuente única, T1)."
    )


@pytest.mark.parametrize(
    "service_path", _API_SERVICES, ids=[p.name for p in _API_SERVICES]
)
def test_t1_servicio_no_codifica_localhost_8000(service_path):
    """
    Ningún servicio codifica `http://localhost:8000` a mano: ese literal vive
    SOLO en config/api.ts (default de desarrollo). Era el bug de las 8 copias
    que obligaba a publicar el puerto 8000 del contenedor (T1).
    """
    src = service_path.read_text(encoding="utf-8")
    assert "localhost:8000" not in src, (
        f"{service_path.name} codifica 'localhost:8000' a mano en vez de usar "
        f"API_BASE_URL (T1)."
    )


# =====================================================================
# A2-d — el <script> inline de window.DjangoData lleva el nonce de la CSP
# =====================================================================

def test_a2d_djangodata_script_lleva_nonce(base_html):
    """
    Se localiza el `<script>` que abre el bloque de `window.DjangoData` y se
    afirma que ESE tag lleva `nonce="{{ request.csp_nonce }}"`. No basta con que
    el nonce aparezca en algún sitio del fichero: tiene que estar en el tag del
    inline que la CSP bloquearía sin él.
    """
    idx = base_html.find("window.DjangoData")
    assert idx != -1, "base.html no contiene el bloque window.DjangoData (A2-d)."

    before = base_html[:idx]
    open_tag_start = before.rfind("<script")
    assert open_tag_start != -1, (
        "No se encuentra el <script> que abre el bloque window.DjangoData (A2-d)."
    )
    open_tag_end = base_html.find(">", open_tag_start)
    open_tag = base_html[open_tag_start : open_tag_end + 1]

    assert re.search(
        r"""nonce\s*=\s*["']\{\{\s*request\.csp_nonce\s*\}\}["']""", open_tag
    ), (
        "El <script> inline de window.DjangoData no lleva "
        'nonce="{{ request.csp_nonce }}"; la CSP (script-src \'self\' sin '
        "unsafe-inline) lo bloquearía y rompería la SPA (A2-d)."
    )
