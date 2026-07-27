"""L1 — batería G de rutas: alcanzabilidad, autorización por defecto y catch-all.

Cubre G1, G2, G3 (§5):

  - G1 Cada ruta con nombre de myapp.urls es reversible y resuelve a una vista
       (ninguna vista inalcanzable). Parametrizado sobre las rutas reales.
  - G2 ⭐ Autorización por defecto: cada ruta responde 401/403 sin autenticar, salvo
       una lista blanca de públicos INTENCIONADOS. Una vista nueva sin
       permission_classes rompe este test el mismo día.
  - G3 El catch-all no debe tragarse la API: /api/<inexistente> debe dar 404, no la
       SPA con 200-HTML.

Nota de divergencia con el plan (manda el código, AUDITORIA/PLAN van por detrás):
  - `metrics` es público a propósito (Prometheus, sin permission_classes); el plan
    no lo listaba en la lista blanca de G2. Se añade con nota. El borde (nginx) es
    quien lo restringe en producción.
  - `api_hibp_range` SÍ exige autenticación en el código (el plan lo listaba como
    público): se trata como protegido.
  - G3: se endureció `app_view` (general_views.py) para que las rutas /api/
    desconocidas devuelvan 404 JSON en vez de la SPA (200-HTML). Antes tragaba la API
    y este test lo cazaba; ahora pasa en verde.
"""

import pytest
from django.urls import resolve, reverse

import myapp.urls

pytestmark = pytest.mark.l1

# Rutas con nombre declaradas por la aplicación (las que barre G1/G2).
_NAMED = [p for p in myapp.urls.urlpatterns if getattr(p, "name", None)]
_IDS = [p.name for p in _NAMED]

# Públicos INTENCIONADOS (no deben exigir 401/403). El resto SÍ.
_WHITELIST = {
    "app", "app_catchall",              # SPA (enrutado en cliente): sirve base.html
    "csrf_token", "health_check",       # AllowAny a propósito (GET → 200)
    "api_login", "api_register",        # login/registro públicos (POST); GET → 405
    "token_refresh",                    # renovación pública por cookie (POST); GET → 405
    "metrics",                          # Prometheus público (sin permission_classes)
}


def _sample_kwargs(pattern):
    """Argumentos de ejemplo para reverse(), según el conversor de cada parámetro."""
    kwargs = {}
    for name, conv in pattern.pattern.converters.items():
        cname = type(conv).__name__
        if "Int" in cname:
            kwargs[name] = 1
        elif "UUID" in cname:
            kwargs[name] = "12345678-1234-5678-1234-567812345678"
        elif "Path" in cname:
            kwargs[name] = "foo/bar"
        else:  # String, Slug
            kwargs[name] = "sample"
    return kwargs


# --------------------------------------------------------------------------- #
# G1 — cada ruta es reversible y resuelve a una vista
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("pattern", _NAMED, ids=_IDS)
def test_g1_ruta_reversible_y_resoluble(pattern):
    url = reverse(pattern.name, kwargs=_sample_kwargs(pattern))
    match = resolve(url)
    assert match.func is not None, f"La ruta {pattern.name} ({url}) no resuelve a una vista."


# --------------------------------------------------------------------------- #
# G2 — autorización por defecto (401/403 sin autenticar, salvo lista blanca)
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
@pytest.mark.parametrize("pattern", _NAMED, ids=_IDS)
def test_g2_autorizacion_por_defecto(pattern, client):
    if pattern.name in _WHITELIST:
        pytest.skip(f"{pattern.name}: público a propósito (lista blanca de G2).")

    url = reverse(pattern.name, kwargs=_sample_kwargs(pattern))
    response = client.get(url)
    assert response.status_code in (401, 403), (
        f"{pattern.name} ({url}) debe exigir autenticación sin token (401/403); "
        f"status={response.status_code}. Una vista sin permission_classes se cuela aquí."
    )


# --------------------------------------------------------------------------- #
# G3 — el catch-all no traga la API
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_g3_catch_all_no_traga_la_api(client):
    response = client.get("/api/ruta-que-no-existe-xyz/")
    assert response.status_code == 404, (
        "Una /api/ inexistente debe dar 404, no la SPA; "
        f"status={response.status_code}, content-type={response.headers.get('Content-Type')!r}"
    )
    # Y la respuesta es JSON, no la SPA en HTML.
    assert "application/json" in response.headers.get("Content-Type", ""), (
        f"El 404 de /api/ debe ser JSON, no HTML; content-type="
        f"{response.headers.get('Content-Type')!r}"
    )
