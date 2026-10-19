"""L1 — cableado del rate limiting y de la atribución de eventos (N3).

A diferencia de `test_middleware.py`, que prueba la lógica de cada middleware por
separado, aquí cada petición atraviesa la cadena REAL con `Client`: lo que se fija
es el cableado (orden de MIDDLEWARE, quién ve a `request.user`, qué limitador
contesta), que es justo lo que fallaba sin que ningún test unitario lo notase.

  - N3  El orden de MIDDLEWARE deja a `request.user` resuelto para los middleware
        que lo leen; un `SecurityEvent` lleva el usuario autenticado, tanto por
        sesión como por JWT.

Las IPs de cliente se simulan como en producción: `REMOTE_ADDR` es la de nginx
(TRUSTED_PROXIES) y la del cliente llega en `X-Forwarded-For`.
"""

import pytest
from django.test import Client
from rest_framework_simplejwt.tokens import AccessToken

import myapp.utils.request_utils as request_utils
from demo import settings as prod
from myapp.models import SecurityEvent

pytestmark = pytest.mark.l1

NGINX_IP = "172.28.0.10"


@pytest.fixture(autouse=True)
def _nginx_de_confianza(settings):
    # `_get_trusted_networks` cachea por proceso: se fija la IP de nginx y se
    # resetea antes y después para que no se filtre a otros tests.
    settings.TRUSTED_PROXIES = [f"{NGINX_IP}/32"]
    settings.TRUSTED_PROXY_HOPS = 1
    request_utils._trusted_networks = None
    yield
    request_utils._trusted_networks = None


def _desde(ip, **extra):
    """Cabeceras de una petición del cliente `ip` que llega a través de nginx."""
    return {"REMOTE_ADDR": NGINX_IP, "HTTP_X_FORWARDED_FOR": ip, **extra}


def _bearer(user):
    return f"Bearer {AccessToken.for_user(user)}"


# --------------------------------------------------------------------------- #
# N3 — orden de MIDDLEWARE
# --------------------------------------------------------------------------- #
def test_n3_orden_de_middleware():
    # Se lee demo.settings, no django.conf.settings (regla dura del §6).
    mw = prod.MIDDLEWARE
    auth = mw.index("django.contrib.auth.middleware.AuthenticationMiddleware")
    jwt = mw.index("myapp.middleware.JWTAuthenticationMiddleware")
    security = mw.index("myapp.middleware.SecurityLoggingMiddleware")
    rate_limit = mw.index("myapp.middleware.RateLimitMiddleware")

    assert auth < security < jwt, (
        "SecurityLoggingMiddleware debe ir tras AuthenticationMiddleware (lee "
        "request.user) y antes de JWTAuthenticationMiddleware (si no, los 401 que "
        "éste corta no pasan por la detección de sondeos)."
    )
    assert jwt < rate_limit, (
        "RateLimitMiddleware debe ir tras JWTAuthenticationMiddleware: si no, no ve "
        "al usuario autenticado por JWT y limita por IP."
    )


# --------------------------------------------------------------------------- #
# N3 — el SecurityEvent lleva el usuario autenticado
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n3_evento_de_seguridad_con_usuario_de_sesion(zk_user):
    client = Client()
    client.force_login(zk_user.user)

    # Ruta de sondeo que acaba en el catch-all de la SPA, una vista de Django
    # que no reautentica: el usuario es el de la sesión.
    client.get("/wp-admin/", **_desde("198.51.100.40"))

    event = SecurityEvent.objects.get(event_type="suspicious_activity")
    assert event.user_id == zk_user.user.id


@pytest.mark.django_db
def test_n3_evento_de_seguridad_con_usuario_jwt(zk_user):
    # Sin sesión de Django: el usuario sólo existe tras JWTAuthenticationMiddleware.
    Client().put(
        "/api/vaults/",
        **_desde("198.51.100.41", HTTP_AUTHORIZATION=_bearer(zk_user.user)),
    )

    event = SecurityEvent.objects.get(event_type="suspicious_activity")
    assert event.user_id == zk_user.user.id
