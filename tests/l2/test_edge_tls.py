"""L2 · stack_prod · Borde TLS y cabeceras (mide NGINX + la app tras él).

  - A2-c  CSP con nonce en script-src, sin unsafe-inline/unsafe-eval (prod).
  - A12-b http://localhost/ -> 301 a https:// (autofirmado, verify=False).
  - A12-c 10 peticiones a /auth/login/ por el 443 -> 429 (mide nginx; contraparte
          de A3-b, que ataca web:8000). SERIAL: agota el presupuesto de auth por IP,
          corre la última y aparte (§6).
  - T2    HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy y COOP
          aparecen EXACTAMENTE una vez (nginx add_header AÑADE; sin duplicados).
  - T4    HSTS max-age con COTA SUPERIOR: corto en local, sin includeSubDomains/
          preload. Nunca fuerza un valor largo (trampa 6).
  - T1-d ⭐ GET https://localhost/ -> 200 y el <script src> del HTML responde 200:
          la cadena Vite->collectstatic->whitenoise->nginx entera, nunca probada.
  - C5-b  `manage.py check --deploy` sin W009/DEBUG y, con TLS, sin W004/W008/W012/W016.

stack_prod se estrena aquí (§1): es la primera vez que se ejerce el TLS de nginx.
"""

import re
from urllib.parse import urljoin, urlparse

import pytest

from _l2lib import (
    BASE_URL_PROD,
    BASE_URL_PROD_HTTP,
    compose_run,
    csrf_headers,
)

pytestmark = [pytest.mark.l2, pytest.mark.stack_prod]


# --------------------------------------------------------------------------- #
# Utilidades de cabeceras.
# --------------------------------------------------------------------------- #
def _header_list(response, name):
    """Lista de valores de una cabecera SIN colapsar duplicados.

    requests une los duplicados con ', ', lo que es ambiguo en cabeceras que ya
    llevan comas (Permissions-Policy). urllib3 expone getlist sobre la respuesta
    cruda, que distingue de verdad si la cabecera vino dos veces (T2)."""
    try:
        values = list(response.raw.headers.getlist(name))
        if values:
            return values
    except Exception:
        pass
    v = response.headers.get(name)
    return [v] if v is not None else []


def _parse_csp(header):
    """Content-Security-Policy -> {directiva: [fuentes]}."""
    directivas = {}
    for parte in header.split(";"):
        parte = parte.strip()
        if not parte:
            continue
        tokens = parte.split()
        directivas[tokens[0].lower()] = tokens[1:]
    return directivas


# --------------------------------------------------------------------------- #
# A2-c — CSP estricta con nonce en producción.
# --------------------------------------------------------------------------- #
def test_a2c_csp_nonce_sin_unsafe(http):
    r = http.get(BASE_URL_PROD + "/", timeout=15)
    assert r.status_code == 200, f"GET / devolvió {r.status_code}"

    csp = r.headers.get("Content-Security-Policy")
    assert csp, "no llegó la cabecera Content-Security-Policy (la emite django-csp)"

    directivas = _parse_csp(csp)
    assert "script-src" in directivas, f"CSP sin script-src: {csp}"
    script_src = " ".join(directivas["script-src"]).lower()

    assert "'nonce-" in script_src, (
        f"script-src sin nonce por respuesta: {directivas['script-src']}"
    )
    assert "'unsafe-inline'" not in script_src, (
        f"script-src con 'unsafe-inline' en producción: {directivas['script-src']}"
    )
    assert "'unsafe-eval'" not in script_src, (
        f"script-src con 'unsafe-eval' en producción: {directivas['script-src']}"
    )
    # default-src 'self' de base.
    assert directivas.get("default-src") == ["'self'"], (
        f"default-src inesperado: {directivas.get('default-src')}"
    )


# --------------------------------------------------------------------------- #
# A12-b — :80 sólo redirige a https.
# --------------------------------------------------------------------------- #
def test_a12b_http_redirige_a_https(http):
    r = http.get(BASE_URL_PROD_HTTP + "/", allow_redirects=False, timeout=15)
    assert r.status_code == 301, f"esperado 301 en :80, llegó {r.status_code}"
    location = r.headers.get("Location", "")
    assert location.startswith("https://"), f"Location no apunta a https://: {location!r}"


# --------------------------------------------------------------------------- #
# A12-c — rate limit de NGINX en /auth/login/. SERIAL (agota el presupuesto).
# --------------------------------------------------------------------------- #
@pytest.mark.serial
def test_a12c_nginx_rate_limit_login(http):
    # GET (no POST): el 443 lo limita antes de llegar a Django, así que basta con
    # tocar la ruta; GET evita registrar intentos de login fallidos en la BD.
    codigos = []
    for _ in range(12):
        r = http.get(BASE_URL_PROD + "/auth/login/", timeout=15)
        codigos.append(r.status_code)
    assert 429 in codigos, (
        f"nginx no cortó /auth/login/ con 429 tras 12 peticiones seguidas: {codigos}. "
        "Debería limitar a 5r/m (burst 5) por IP en auth_zone (A12-c)."
    )


# --------------------------------------------------------------------------- #
# T2 — cada cabecera de seguridad, exactamente una vez.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "cabecera",
    [
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
    ],
)
def test_t2_cabeceras_sin_duplicar(http, cabecera):
    r = http.get(BASE_URL_PROD + "/", timeout=15)
    assert r.status_code == 200, f"GET / devolvió {r.status_code}"
    valores = _header_list(r, cabecera)
    assert len(valores) == 1, (
        f"{cabecera} aparece {len(valores)} veces ({valores}); debe aparecer una sola "
        "vez. nginx add_header AÑADE: repetir una que Django ya emite la duplica (T2)."
    )


# --------------------------------------------------------------------------- #
# T4 — HSTS: cota superior. Nunca exige un valor largo (trampa 6).
# --------------------------------------------------------------------------- #
_UN_ANIO = 31536000


def test_t4_hsts_cota_superior(http):
    r = http.get(BASE_URL_PROD + "/", timeout=15)
    hsts = r.headers.get("Strict-Transport-Security", "")
    assert hsts, "no llegó Strict-Transport-Security (la emite Django con TLS activo)"

    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
    assert m, f"HSTS sin max-age numérico: {hsts!r}"
    max_age = int(m.group(1))

    # SÓLO cota superior: se afirma que NO es de un año o más en local; jamás se
    # exige que sea largo (eso es para el dominio real, no para localhost).
    assert max_age < _UN_ANIO, (
        f"max-age={max_age} >= 1 año sobre localhost: HSTS se aplica por host e "
        "ignora el puerto, así clavaría https en cualquier proyecto local (trampa 6)."
    )
    assert "includesubdomains" not in hsts.lower(), (
        f"includeSubDomains con max-age corto: {hsts!r}"
    )
    assert "preload" not in hsts.lower(), f"preload con max-age corto: {hsts!r}"


# --------------------------------------------------------------------------- #
# T1-d ⭐ — la cadena de assets entera: Vite -> collectstatic -> whitenoise -> nginx.
# --------------------------------------------------------------------------- #
def _extraer_assets(html):
    """URLs de <script src> y <link rel=stylesheet href> del HTML."""
    scripts = re.findall(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']', html, re.I)
    links = []
    for tag in re.findall(r"<link\b[^>]*>", html, re.I):
        if "stylesheet" in tag.lower():
            m = re.search(r'\bhref\s*=\s*["\']([^"\']+)["\']', tag, re.I)
            if m:
                links.append(m.group(1))
    return scripts, links


def test_t1d_cadena_de_assets_responde(http):
    r = http.get(BASE_URL_PROD + "/", timeout=15)
    assert r.status_code == 200, f"GET / devolvió {r.status_code}"
    assert "text/html" in r.headers.get("Content-Type", ""), (
        f"/ no devolvió HTML: {r.headers.get('Content-Type')!r}"
    )

    scripts, links = _extraer_assets(r.text)
    assert scripts, (
        "el HTML de / no referencia ningún <script src>: la SPA no se está sirviendo "
        "(¿collectstatic no corrió o el manifest de Vite falta?)."
    )

    base_netloc = urlparse(BASE_URL_PROD).netloc  # 'localhost'
    cross_origin = []
    for ref in scripts + links:
        parsed = urlparse(ref)
        if parsed.scheme and parsed.netloc and parsed.netloc != base_netloc:
            cross_origin.append(ref)

    assert not cross_origin, (
        f"assets cross-origin en producción: {cross_origin}. Apuntan fuera de "
        f"{base_netloc}, lo que delata DJANGO_VITE_DEV_MODE=true filtrado a prod "
        "(el dev server de Vite en :5174). La cadena Vite->collectstatic->whitenoise->"
        "nginx exige assets same-origin construidos."
    )

    for ref in scripts + links:
        url = urljoin(BASE_URL_PROD + "/", ref)
        ra = http.get(url, timeout=15)
        assert ra.status_code == 200, (
            f"el asset {url} respondió {ra.status_code}; la cadena de estáticos está "
            "rota (whitenoise/nginx no lo sirve)."
        )


# --------------------------------------------------------------------------- #
# C5-b — check --deploy sin los avisos que la Fase 1 cerró con TLS.
# --------------------------------------------------------------------------- #
# W009 SECRET_KEY débil · W018 DEBUG · W004 HSTS · W008 SSL redirect ·
# W012 SESSION_COOKIE_SECURE · W016 CSRF_COOKIE_SECURE.
_AVISOS_PROHIBIDOS = ["W009", "W018", "W004", "W008", "W012", "W016"]


def test_c5b_check_deploy_limpio(compose_cmd, backend_dir):
    res = compose_run(
        compose_cmd,
        backend_dir,
        ["exec", "-T", "web", "python", "manage.py", "check", "--deploy"],
        timeout=120,
    )
    salida = (res.stdout or "") + "\n" + (res.stderr or "")
    assert salida.strip(), f"`check --deploy` no produjo salida (rc={res.returncode})"

    presentes = [aviso for aviso in _AVISOS_PROHIBIDOS if aviso in salida]
    assert not presentes, (
        f"`manage.py check --deploy` emite avisos que deberían estar cerrados en "
        f"stack_prod (TLS activo, DEBUG=false): {presentes}.\nSalida:\n{salida.strip()[:2000]}"
    )
