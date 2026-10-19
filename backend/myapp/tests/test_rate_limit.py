"""L1 — cableado del rate limiting y de la atribución de eventos (N3, N5).

A diferencia de `test_middleware.py`, que prueba la lógica de cada middleware por
separado, aquí cada petición atraviesa la cadena REAL con `Client`: lo que se fija
es el cableado (orden de MIDDLEWARE, quién ve a `request.user`, qué limitador
contesta), que es justo lo que fallaba sin que ningún test unitario lo notase.

  - N3  El orden de MIDDLEWARE deja a `request.user` resuelto para los middleware
        que lo leen; un `SecurityEvent` lleva el usuario autenticado, tanto por
        sesión como por JWT.
  - N5  Con Redis caído, el limitador falla cerrado (503 y log) y las rutas que no
        limita siguen respondiendo (antes, los throttles de DRF daban 500).

Las IPs de cliente se simulan como en producción: `REMOTE_ADDR` es la de nginx
(TRUSTED_PROXIES) y la del cliente llega en `X-Forwarded-For`.
"""

import logging
from contextlib import ExitStack
from unittest import mock

import pytest
from django.core.cache import caches
from django.test import Client
from redis.exceptions import ConnectionError as RedisConnectionError
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


# --------------------------------------------------------------------------- #
# N5 — Redis caído: fallo cerrado donde se limita, servicio donde no
# --------------------------------------------------------------------------- #
@pytest.fixture
def redis_caido():
    error = mock.Mock(side_effect=RedisConnectionError("Redis caído (test)"))
    with ExitStack() as stack:
        for name in ("default", "sessions"):
            for method in ("get", "set", "add", "incr", "delete", "get_many"):
                stack.enter_context(mock.patch.object(caches[name], method, error))
        yield


@pytest.fixture
def security_log(caplog):
    # El logger 'security' no propaga a la raíz (LOGGING), así que caplog no lo
    # ve si no se le engancha directamente.
    logger = logging.getLogger("security")
    logger.addHandler(caplog.handler)
    yield caplog
    logger.removeHandler(caplog.handler)


@pytest.mark.django_db
def test_n5_redis_caido_falla_cerrado_donde_limita_y_no_tumba_el_resto(
    zk_user, redis_caido, security_log
):
    client = Client(raise_request_exception=False)

    r = client.post(
        "/auth/login/", data="{}", content_type="application/json",
        **_desde("198.51.100.50"),
    )
    assert r.status_code == 503
    assert any(
        rec.levelno >= logging.ERROR and "Rate limiting no disponible" in rec.getMessage()
        for rec in security_log.records
    ), "la denegación por caché caída debe quedar en el log de seguridad"

    r = client.get(
        "/api/accounts/",
        **_desde("198.51.100.51", HTTP_AUTHORIZATION=_bearer(zk_user.user)),
    )
    assert r.status_code == 200, (
        f"/api/accounts/ no está limitado: una caída de Redis no debe tumbarlo ({r.status_code})"
    )
