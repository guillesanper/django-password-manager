"""L1 — middleware con RequestFactory / Client.

Cubre A3-a, A4-b, M12 y G7 (§4.3/§4.4/§5):

  - A3-a classify_endpoint devuelve 'sensitive' para las ESCRITURAS a las rutas que
        validan la maestra (setup/change, add/delete de passwords); '/api/master-key/
        verify/' cae en 'auth'. Las lecturas no se sobre-limitan.
  - A4-b get_client_ip: con REMOTE_ADDR público se ignora X-Forwarded-For; con un
        proxy de confianza se toma la posición TRUSTED_PROXY_HOPS DESDE LA DERECHA, de
        modo que una entrada inyectada por el cliente no cuenta.
  - M12  detect_suspicious_request NO bloquea por subcadenas ';' / '--' / 'DELETE' en
        el cuerpo: mira ruta+método+UA, nunca el contenido (que es material secreto).
  - G7   Una petición autenticada atraviesa la cadena de middleware (los 8 de
        myapp.middleware + CSPMiddleware) sin lanzar excepción.

Ninguno es xfail: con las Fases 0-2 cerradas todos deben pasar hoy (§3).
"""

import pytest
from django.conf import settings
from django.test import Client, RequestFactory, override_settings
from rest_framework_simplejwt.tokens import AccessToken

import myapp.utils.request_utils as request_utils
from myapp.middleware import RateLimitMiddleware, SecurityLoggingMiddleware
from myapp.utils.request_utils import get_client_ip

pytestmark = pytest.mark.l1

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


# --------------------------------------------------------------------------- #
# A3-a — classify_endpoint marca 'sensitive' las escrituras de la maestra
# --------------------------------------------------------------------------- #
def test_a3a_classify_endpoint_rutas_maestra():
    rf = RequestFactory()
    mw = RateLimitMiddleware(lambda r: None)

    def classify(method, path):
        request = getattr(rf, method.lower())(path)
        return mw.classify_endpoint(request, path)

    # Escrituras que validan la contraseña maestra → 'sensitive' (con rate limit).
    assert classify("POST", "/api/master-key/setup/") == "sensitive"
    assert classify("POST", "/api/master-key/change/") == "sensitive"
    assert classify("POST", "/api/passwords/add/") == "sensitive"
    assert classify("DELETE", "/api/passwords/5/delete/") == "sensitive"
    assert classify("POST", "/api/batch-delete-passwords/") == "sensitive"

    # '/api/master-key/verify/' entra en el cubo 'auth' (10 por 5 min), también limitado.
    assert classify("POST", "/api/master-key/verify/") == "auth"

    # Las LECTURAS no verifican nada y no deben caer en 'sensitive'.
    assert classify("GET", "/api/passwords/unvaulted/") == "normal"


# --------------------------------------------------------------------------- #
# A4-b — get_client_ip cuenta los saltos desde la derecha
# --------------------------------------------------------------------------- #
def _ip(rf, remote_addr, xff=None):
    extra = {"REMOTE_ADDR": remote_addr}
    if xff is not None:
        extra["HTTP_X_FORWARDED_FOR"] = xff
    return get_client_ip(rf.get("/api/accounts/", **extra))


def test_a4b_get_client_ip_hops_desde_la_derecha():
    rf = RequestFactory()
    # `_get_trusted_networks` cachea el resultado por proceso; se resetea para que el
    # override de TRUSTED_PROXIES surta efecto y no se filtre a otros tests.
    try:
        with override_settings(
            TRUSTED_PROXIES=["172.28.0.10/32"], TRUSTED_PROXY_HOPS=1
        ):
            request_utils._trusted_networks = None

            # Par TCP público (no es proxy de confianza): X-Forwarded-For se ignora.
            assert _ip(rf, "198.51.100.7", xff="9.9.9.9") == "198.51.100.7"

            # Proxy de confianza, un salto: la IP la escribió nginx, no el cliente.
            assert _ip(rf, "172.28.0.10", xff="198.51.100.23") == "198.51.100.23"

            # El cliente inyecta '6.6.6.6' y nginx AÑADE la IP real a su derecha.
            # Con hops=1 se toma la penúltima (la real), nunca la inyectada.
            assert (
                _ip(rf, "172.28.0.10", xff="6.6.6.6, 198.51.100.23")
                == "198.51.100.23"
            )

        request_utils._trusted_networks = None
        with override_settings(
            TRUSTED_PROXIES=["172.28.0.10/32"], TRUSTED_PROXY_HOPS=2
        ):
            request_utils._trusted_networks = None
            # Dos saltos (CDN + nginx): la IP real está 2 posiciones desde la derecha;
            # la entrada inyectada por el cliente (izquierda) sigue sin contar.
            assert (
                _ip(
                    rf,
                    "172.28.0.10",
                    xff="6.6.6.6, 198.51.100.23, 203.0.113.9",
                )
                == "198.51.100.23"
            )
    finally:
        request_utils._trusted_networks = None


# --------------------------------------------------------------------------- #
# M12 — detect_suspicious_request no mira el cuerpo (';' / '--' / 'DELETE')
# --------------------------------------------------------------------------- #
def test_m12_no_bloquea_por_subcadenas_en_el_cuerpo():
    rf = RequestFactory()
    mw = SecurityLoggingMiddleware(lambda r: None)

    # Un POST legítimo cuyo cuerpo contiene ';', '--' y 'DELETE' (una contraseña
    # generada, o una nota): NO debe señalizarse. El detector no lee el cuerpo.
    request = rf.post(
        "/api/passwords/add/",
        data={"password": "aA1$b;c--dZ", "note": "DROP TABLE users; -- DELETE"},
    )
    signals, is_probe = mw.detect_suspicious_request(request, _UA)
    assert signals == [], f"El cuerpo no debe generar señales de sondeo: {signals}"
    assert is_probe is False

    # Control positivo: una ruta de sondeo real SÍ señaliza (el detector funciona,
    # el test no es vacuo).
    probe = rf.get("/wp-login.php")
    probe_signals, probe_is_probe = mw.detect_suspicious_request(probe, _UA)
    assert probe_signals, "Una ruta de sondeo debe generar señales."
    assert probe_is_probe is True


# --------------------------------------------------------------------------- #
# G7 — una petición autenticada atraviesa la cadena de middleware sin excepción
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_g7_cadena_middleware_atravesada_sin_excepcion(zk_user):
    # Se autentica con el mecanismo REAL de la app: el access token en la cookie
    # HttpOnly (CookieJWTAuthentication), no una sesión de Django. Así la petición
    # ejerce de verdad la rama autenticada de JWTAuthenticationMiddleware.
    token = str(AccessToken.for_user(zk_user.user))
    client = Client()
    client.cookies[settings.JWT_AUTH_COOKIE] = token

    # GET /api/vaults/ está tras JWTAuthenticationMiddleware y la validación de sesión;
    # con la cookie válida atraviesa la cadena completa (los 8 middleware de
    # myapp + CSPMiddleware). GET es método seguro, así que no se exige CSRF. Si algún
    # middleware lanzara, el Client (raise_request_exception=True) haría fallar el test.
    response = client.get("/api/vaults/")

    assert response.status_code == 200, (
        "La petición autenticada debe atravesar la cadena de middleware sin error; "
        f"status={response.status_code}, cuerpo={response.content[:200]!r}"
    )
