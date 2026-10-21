"""L1 — cerrar sesión nunca falla cerrado (N10).

Cada petición atraviesa la cadena REAL con `Client`, como en `test_rate_limit.py`. El
navegador se simula con las cookies `access_token` y `refresh_token`.

  - N10   El logout estaba en el cubo `auth` del limitador: tras 10 operaciones de ese cubo
          o con Redis caído daba 429/503 y las cookies seguían vivas. Con el access caducado
          daba 401 y dependía de renovar en `/api/token/refresh/`, que sí se limita. Ahora no
          se limita, basta el refresh para cerrar sesión, responde 200 y borra las cookies.
          Sin access válido sigue exigiendo CSRF.

La otra mitad de N10, que el cliente no da la sesión por cerrada si el servidor no lo
confirma, la cubre `frontend/src/services/authService.test.ts` (L3).
"""

from contextlib import ExitStack
from datetime import timedelta
from unittest import mock

import pytest
from django.conf import settings
from django.core.cache import caches
from django.test import Client
from redis.exceptions import ConnectionError as RedisConnectionError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken

from myapp.middleware import RateLimitMiddleware
from myapp.utils import request_utils

pytestmark = pytest.mark.l1

NGINX_IP = "172.28.0.10"
CLIENTE_IP = "198.51.100.70"


@pytest.fixture(autouse=True)
def _nginx_de_confianza(settings):
    # Mismo montaje que test_rate_limit.py: la IP del cliente llega en X-Forwarded-For.
    settings.TRUSTED_PROXIES = [f"{NGINX_IP}/32"]
    settings.TRUSTED_PROXY_HOPS = 1
    request_utils._trusted_networks = None
    yield
    request_utils._trusted_networks = None


@pytest.fixture
def redis_caido():
    error = mock.Mock(side_effect=RedisConnectionError("Redis caído (test)"))
    with ExitStack() as stack:
        for name in ("default", "sessions"):
            for method in ("get", "set", "add", "incr", "delete", "get_many"):
                stack.enter_context(mock.patch.object(caches[name], method, error))
        yield


def _navegador(user, access_caducado=False):
    """Client con las cookies de un login y el refresh emitido, para comprobar si se invalida."""
    refresh = RefreshToken.for_user(user)
    access = refresh.access_token
    if access_caducado:
        access.set_exp(lifetime=-timedelta(minutes=1))
    client = Client(raise_request_exception=False)
    client.cookies[settings.JWT_AUTH_COOKIE] = str(access)
    client.cookies[settings.JWT_AUTH_REFRESH_COOKIE] = str(refresh)
    return client, refresh


def _logout(client):
    return client.post(
        "/auth/logout/", REMOTE_ADDR=NGINX_IP, HTTP_X_FORWARDED_FOR=CLIENTE_IP,
    )


def _assert_cerrada(r, refresh):
    assert r.status_code == 200, f"el logout respondió {r.status_code}: {r.content[:300]}"
    for nombre in (settings.JWT_AUTH_COOKIE, settings.JWT_AUTH_REFRESH_COOKIE):
        assert r.cookies[nombre]["max-age"] == 0, f"el logout no borró la cookie {nombre}"
    assert BlacklistedToken.objects.filter(token__jti=refresh["jti"]).exists(), (
        "el refresh de este navegador sigue vivo tras cerrar sesión"
    )


# --------------------------------------------------------------------------- #
# N10 — el logout no se limita ni depende de Redis
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n10_logout_con_el_cubo_auth_agotado(zk_user):
    # Se agota el cubo desde la misma IP con renovaciones, que sí cuentan.
    maximo = RateLimitMiddleware.LIMITS["auth"][0]
    anonimo = Client(raise_request_exception=False)
    for _ in range(maximo):
        anonimo.post("/api/token/refresh/", REMOTE_ADDR=NGINX_IP, HTTP_X_FORWARDED_FOR=CLIENTE_IP)
    r = anonimo.post("/api/token/refresh/", REMOTE_ADDR=NGINX_IP, HTTP_X_FORWARDED_FOR=CLIENTE_IP)
    assert r.status_code == 429, "el montaje no agotó el cubo 'auth'"

    client, refresh = _navegador(zk_user.user)
    _assert_cerrada(_logout(client), refresh)


@pytest.mark.django_db
def test_n10_logout_con_redis_caido(zk_user, redis_caido):
    client, refresh = _navegador(zk_user.user)
    _assert_cerrada(_logout(client), refresh)


# --------------------------------------------------------------------------- #
# N10 — basta el refresh para cerrar sesión
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n10_logout_con_el_access_caducado_invalida_el_refresh(zk_user):
    client, refresh = _navegador(zk_user.user, access_caducado=True)
    _assert_cerrada(_logout(client), refresh)


@pytest.mark.django_db
def test_n10_logout_sin_credenciales_validas_borra_las_cookies(zk_user):
    client, _ = _navegador(zk_user.user, access_caducado=True)
    client.cookies[settings.JWT_AUTH_REFRESH_COOKIE] = "no-es-un-token"

    r = _logout(client)

    assert r.status_code == 200, f"el logout respondió {r.status_code}"
    assert r.cookies[settings.JWT_AUTH_REFRESH_COOKIE]["max-age"] == 0


@pytest.mark.django_db
def test_n10_logout_sin_access_sigue_exigiendo_csrf(zk_user):
    # Al no exigir access, el CSRF ya no lo pone la clase de autenticación: lo pone la vista.
    _, refresh = _navegador(zk_user.user, access_caducado=True)
    client = Client(enforce_csrf_checks=True, raise_request_exception=False)
    client.cookies[settings.JWT_AUTH_REFRESH_COOKIE] = str(refresh)

    r = _logout(client)

    assert r.status_code == 403, f"logout sin CSRF respondió {r.status_code}"
    assert not BlacklistedToken.objects.filter(token__jti=refresh["jti"]).exists()
