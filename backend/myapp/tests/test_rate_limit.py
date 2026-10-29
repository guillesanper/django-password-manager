"""L1 — cableado del rate limiting y de la atribución de eventos (N3, N4, N5).

A diferencia de `test_middleware.py`, que prueba la lógica de cada middleware por
separado, aquí cada petición atraviesa la cadena REAL con `Client`: lo que se fija
es el cableado (orden de MIDDLEWARE, quién ve a `request.user`, qué limitador
contesta), que es justo lo que fallaba sin que ningún test unitario lo notase.

  - N3  El orden de MIDDLEWARE deja a `request.user` resuelto para los middleware
        que lo leen; un `SecurityEvent` lleva el usuario autenticado, tanto por
        sesión como por JWT.
  - N4  Un único limitador: por IP real (vía `get_client_ip`, detrás de nginx)
        cuando no hay usuario y por usuario cuando lo hay. Ni el cubo global por
        `REMOTE_ADDR` de django_ratelimit ni sus 403.
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
from myapp.middleware import RateLimitMiddleware
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
# N4 — por IP real cuando no hay usuario
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n4_ip_por_encima_del_limite_recibe_429_y_solo_ella():
    client = Client()

    # Quince clientes distintos, un intento de login cada uno. El cuerpo vacío no
    # pasa la validación (400) y no ejecuta el hasher.
    for n in range(1, 16):
        r = client.post(
            "/auth/login/", data="{}", content_type="application/json",
            **_desde(f"203.0.113.{n}"),
        )
        assert r.status_code == 400, f"cliente {n}: {r.status_code}"

    # Un decimosexto cliente no ha gastado nada: no puede estar limitado. Con
    # @ratelimit(key='ip') el contador era el de REMOTE_ADDR, es decir el de
    # nginx, compartido por todos (403 al decimosexto login del mundo).
    r = client.post(
        "/auth/login/", data="{}", content_type="application/json",
        **_desde("203.0.113.16"),
    )
    assert r.status_code == 400, f"un cliente nuevo no debe estar limitado: {r.status_code}"

    # La IP que sí se pasa recibe 429. Se usa la renovación de token, del mismo
    # cubo 'auth', porque el login tiene además su bloqueo por fallos.
    limite = RateLimitMiddleware.LIMITS["auth"][0]
    for i in range(limite):
        r = client.post("/api/token/refresh/", **_desde("203.0.113.99"))
        assert r.status_code != 429, f"petición {i + 1} de {limite} limitada antes de tiempo"
    r = client.post("/api/token/refresh/", **_desde("203.0.113.99"))
    assert r.status_code == 429

    r = client.post("/api/token/refresh/", **_desde("203.0.113.100"))
    assert r.status_code != 429, "el límite de una IP no debe alcanzar a otra"


# --------------------------------------------------------------------------- #
# N4 — por usuario cuando lo hay
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n4_usuario_por_encima_del_limite_recibe_429_aunque_rote_de_ip(
    zk_user, django_user_model
):
    client = Client()
    auth = _bearer(zk_user.user)
    limite = RateLimitMiddleware.LIMITS["sensitive"][0]

    # Cuerpo vacío: la vista contesta 400 sin tocar nada, pero la escritura cuenta
    # en el cubo 'sensitive'. Cada petición sale de una IP distinta.
    for i in range(limite):
        r = client.post(
            "/api/passwords/add/", data="{}", content_type="application/json",
            **_desde(f"10.9.{i // 250}.{i % 250 + 1}", HTTP_AUTHORIZATION=auth),
        )
        assert r.status_code != 429, f"petición {i + 1} de {limite} limitada antes de tiempo"

    r = client.post(
        "/api/passwords/add/", data="{}", content_type="application/json",
        **_desde("10.9.99.1", HTTP_AUTHORIZATION=auth),
    )
    assert r.status_code == 429, "rotar de IP no debe esquivar el límite por usuario"

    # Otro usuario desde la misma IP no comparte cubo.
    other = django_user_model.objects.create_user(
        username="zk_tester_beta", email="zk_tester_beta@example.test",
        password="Wren$Kilo7pluto",
    )
    r = client.post(
        "/api/passwords/add/", data="{}", content_type="application/json",
        **_desde("10.9.99.1", HTTP_AUTHORIZATION=_bearer(other)),
    )
    assert r.status_code != 429


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
