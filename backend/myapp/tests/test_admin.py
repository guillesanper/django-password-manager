"""L1 — /admin/ desactivado salvo que se pida (N18, AU-22).

`/admin/login/` era público, sin `limit_req` en nginx, fuera de `RateLimitMiddleware` y del
bloqueo del login: con un superusuario, fuerza bruta online a unos 30 intentos por segundo. Y un
administrador puede reescribir `kdf_params` (AU-09). El SPA no lo usa. Ahora sólo se monta con
DJANGO_ADMIN_ENABLED=true, y entonces nginx le aplica el límite del login (L0).
"""

import importlib

import pytest
from django.urls import clear_url_caches, resolve

import demo.urls
from demo import settings as prod_settings

pytestmark = pytest.mark.l1


@pytest.fixture
def urls_con(settings):
    def recargar(activado):
        settings.ADMIN_ENABLED = activado
        importlib.reload(demo.urls)
        clear_url_caches()
    yield recargar
    settings.ADMIN_ENABLED = prod_settings.ADMIN_ENABLED
    importlib.reload(demo.urls)
    clear_url_caches()


def test_n18_admin_desactivado_por_defecto():
    assert prod_settings.ADMIN_ENABLED is False


def test_n18_sin_activar_no_hay_admin(urls_con):
    urls_con(False)
    match = resolve("/admin/login/")
    assert match.app_name != "admin", "/admin/ sigue montado"
    assert match.url_name == "app_catchall"  # cae en la SPA, como cualquier ruta desconocida


def test_n18_activado_se_monta(urls_con):
    urls_con(True)
    assert resolve("/admin/login/").app_name == "admin"
