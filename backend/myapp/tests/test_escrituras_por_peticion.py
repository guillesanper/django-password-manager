"""L1 — una lectura no escribe y la auditoría registra lo que pasó (N15).

Cada petición atraviesa la cadena REAL con `Client`, con logins por `/auth/login/` cuando
importa lo que hace el login.

  - N15   Cada GET autenticado hacía de 7 a 16 consultas, de ellas 2 o 3 escrituras:
          `SessionSecurityMiddleware` guardaba la sesión Django (que `login()` abría en el
          login del SPA y `SESSION_SAVE_EVERY_REQUEST` reescribía), y `AuditMiddleware`
          insertaba un `ActivityLog` etiquetado por el método HTTP («Contraseña
          visualizada» por un GET de la lista, un segundo «Vault creado» junto al de la
          vista). Un cliente `Bearer` sin cookies creaba una fila de `django_session` por
          petición. El JWT se validaba dos veces (middleware y DRF), con dos consultas a
          `auth_user`.
          La maestra no la registraba ninguna vista: sólo `AuditMiddleware`, que llamaba
          «Clave maestra verificada» a cualquier POST con éxito, también al configurarla.
"""

import pytest
from django.contrib.sessions.models import Session
from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext
from rest_framework_simplejwt.tokens import AccessToken

from myapp.middleware import RateLimitMiddleware
from myapp.models import ActivityLog
from myapp.tests.conftest import TEST_MASTER_PASSWORD, build_user_crypto_material
from myapp.utils import request_utils

pytestmark = pytest.mark.l1

NGINX_IP = "172.28.0.10"
ESCRITURAS = ("INSERT", "UPDATE", "DELETE")
LECTURAS = ("/api/passwords/unvaulted/", "/api/vaults/", "/api/sessions/list/", "/auth/check/")


@pytest.fixture(autouse=True)
def _nginx_de_confianza(settings):
    # Mismo montaje que test_rate_limit.py: la IP del cliente llega en X-Forwarded-For.
    settings.TRUSTED_PROXIES = [f"{NGINX_IP}/32"]
    settings.TRUSTED_PROXY_HOPS = 1
    request_utils._trusted_networks = None
    yield
    request_utils._trusted_networks = None


def _login(zk_user):
    client = Client(raise_request_exception=False)
    r = client.post("/auth/login/", data={
        "email": zk_user.credentials["email"],
        "password": zk_user.credentials["password"],
    }, content_type="application/json")
    assert r.status_code == 200, r.content
    return client


def _consultas(client, path, **extra):
    with CaptureQueriesContext(connection) as ctx:
        r = client.get(path, **extra)
    assert r.status_code == 200, f"{path}: {r.status_code} {r.content[:200]}"
    return [q["sql"] for q in ctx.captured_queries]


def _bearer(user):
    return f"Bearer {AccessToken.for_user(user)}"


# --------------------------------------------------------------------------- #
# N15 — una lectura no escribe
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
@pytest.mark.parametrize("path", LECTURAS)
def test_n15_una_lectura_no_escribe(zk_user, path):
    client = _login(zk_user)
    escrituras = [q for q in _consultas(client, path) if q.lstrip().upper().startswith(ESCRITURAS)]
    assert escrituras == [], f"GET {path} escribe en la BD:\n" + "\n".join(q[:120] for q in escrituras)


@pytest.mark.django_db
@pytest.mark.parametrize("path", LECTURAS)
def test_n15_el_jwt_se_valida_una_sola_vez(zk_user, path):
    client = _login(zk_user)
    consultas = _consultas(client, path)
    usuarios = [q for q in consultas if 'FROM "auth_user"' in q]
    revocaciones = [q for q in consultas if 'FROM "myapp_revokedsession"' in q]
    assert len(usuarios) == 1, f"GET {path} lee auth_user {len(usuarios)} veces"
    assert len(revocaciones) == 1, f"GET {path} comprueba la revocación {len(revocaciones)} veces"


@pytest.mark.django_db
def test_n15_el_login_no_abre_sesion_django(zk_user):
    client = _login(zk_user)
    assert "sessionid" not in client.cookies
    assert not Session.objects.exists()


@pytest.mark.django_db
def test_n15_un_cliente_bearer_no_crea_sesiones(zk_user):
    client = Client(raise_request_exception=False)
    for _ in range(3):
        _consultas(client, "/api/passwords/unvaulted/", HTTP_AUTHORIZATION=_bearer(zk_user.user))
    assert not Session.objects.exists()


# --------------------------------------------------------------------------- #
# N15 — sin la sesión Django, los middleware siguen viendo al usuario del JWT
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n15_la_lista_marca_la_sesion_actual(zk_user):
    sesiones = _login(zk_user).get("/api/sessions/list/").json()["sessions"]["sessions"]
    assert [s.get("is_current", False) for s in sesiones] == [True]


@pytest.mark.django_db
def test_n15_fuera_de_las_rutas_jwt_se_limita_por_usuario(zk_user, monkeypatch):
    """`/api/batch-delete-passwords/` no está en la lista de `JWTAuthenticationMiddleware`.
    Antes sólo contaba por usuario si había sesión Django; un cliente `Bearer` contaba por IP
    y rotar de IP esquivaba el límite."""
    monkeypatch.setitem(RateLimitMiddleware.LIMITS, "sensitive", (2, 3600, "límite"))
    client = Client(raise_request_exception=False)
    estados = [
        client.post(
            "/api/batch-delete-passwords/", data="{}", content_type="application/json",
            REMOTE_ADDR=NGINX_IP, HTTP_X_FORWARDED_FOR=f"10.8.0.{i}",
            HTTP_AUTHORIZATION=_bearer(zk_user.user),
        ).status_code
        for i in range(1, 4)
    ]
    assert estados[:2] != [429, 429] and estados[2] == 429, estados


@pytest.mark.django_db
def test_n15_un_token_invalido_fuera_de_las_rutas_jwt_no_corta_la_peticion(zk_user):
    """Fuera de su lista, el middleware autentica si puede pero no deniega: decide la vista.
    El logout con el access caducado tiene que seguir funcionando (N10)."""
    r = Client(raise_request_exception=False).get(
        "/api/dashboard/stats/", HTTP_AUTHORIZATION="Bearer basura",
    )
    assert r.status_code == 401
    assert b"Token" in r.content or b"token" in r.content


# --------------------------------------------------------------------------- #
# N15 — la auditoría registra lo que pasó, una vez
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n15_una_lectura_no_registra_actividad(zk_user):
    client = _login(zk_user)
    antes = ActivityLog.objects.count()
    for path in LECTURAS:
        _consultas(client, path)
    assert ActivityLog.objects.count() == antes


@pytest.mark.django_db
def test_n15_crear_una_boveda_se_registra_una_vez(zk_user):
    client = _login(zk_user)
    r = client.post("/api/vaults/create/", data={"name": "Trabajo", "color": "blue"},
                    content_type="application/json")
    assert r.status_code in (200, 201), r.content
    tipos = list(ActivityLog.objects.exclude(activity_type="login").values_list("activity_type", flat=True))
    assert tipos == ["vault_created"]


@pytest.mark.django_db
def test_n15_la_maestra_se_registra_con_su_nombre(zk_user, django_user_model):
    usuario = django_user_model.objects.create_user(
        username="maestra_nueva", email="maestra_nueva@example.test", password="x",
    )
    material = build_user_crypto_material(TEST_MASTER_PASSWORD)
    nuevo = build_user_crypto_material(TEST_MASTER_PASSWORD + "2")
    client = Client(raise_request_exception=False, HTTP_AUTHORIZATION=_bearer(usuario))

    def post(path, body):
        r = client.post(path, data=body, content_type="application/json")
        assert r.status_code == 200, r.content

    post("/api/master-key/setup/", {
        "kdf_salt": material["kdf_salt"], "kdf_params": material["kdf_params"],
        "auth_key": material["auth_key_b64"], "wrapped_vault_key": material["wrapped_vault_key"],
    })
    post("/api/master-key/verify/", {"auth_key": material["auth_key_b64"]})
    post("/api/master-key/change/", {
        "current_auth_key": material["auth_key_b64"],
        "kdf_salt": nuevo["kdf_salt"], "kdf_params": nuevo["kdf_params"],
        "auth_key": nuevo["auth_key_b64"], "wrapped_vault_key": nuevo["wrapped_vault_key"],
    })

    tipos = list(
        ActivityLog.objects.filter(user=usuario).order_by("timestamp", "id")
        .values_list("activity_type", flat=True)
    )
    assert tipos == ["master_key_created", "master_key_verified", "master_key_changed"]
