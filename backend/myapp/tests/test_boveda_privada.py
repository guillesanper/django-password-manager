"""L1 — el desbloqueo de una bóveda privada es de la sesión que lo probó (N9).

Cada petición atraviesa la cadena REAL con `Client` y un JWT por Bearer, como en
`test_rate_limit.py`. Dos tokens del mismo usuario con distinto `sid` hacen de dos
navegadores. La bóveda se siembra por ORM con una SubAuthKey cualquiera: el servidor sólo
compara su hash, así que no hace falta derivarla.

  - N9    El marcador de desbloqueo iba por usuario: una sesión que sólo conocía la maestra
          heredaba el desbloqueo de otra y podía leer y meter entradas en la bóveda. Ahora va
          atado al `sid` del login, que se hereda en cada access y sobrevive a la rotación.
          Los tokens anteriores al claim caen al `jti` del access.
          Cambiar la contraseña, hacerla pública o borrarla revoca el desbloqueo en todas las
          sesiones, y si la caché no deja revocar, 503 sin tocar la BD.
          El marcador se renueva con el uso; antes caducaba a los 15 min aunque se usara.

La otra mitad de N9, que el cliente no cifra con la VaultKey principal para una bóveda
privada sin subclave, la cubre `frontend/src/services/cryptoSession.test.ts` (L3).
"""

import base64
import uuid
from contextlib import ExitStack
from unittest import mock

import pytest
from django.core.cache import caches
from django.test import Client
from redis.exceptions import ConnectionError as RedisConnectionError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from myapp.models import PasswordEntry, Vault
from myapp.tests.conftest import KDF_PARAMS
from myapp.utils.login_session import SESSION_ID_CLAIM, stamp_session_id
from myapp.utils.vault_unlock import VAULT_UNLOCK_TTL_SECONDS

pytestmark = pytest.mark.l1

# El servidor sólo guarda y compara el hash de la SubAuthKey: basta un valor fijo. Se codifica
# aquí y no como literal base64 para que los escáneres de secretos no lo tomen por una clave.
SUB_AUTH_KEY = base64.b64encode(b"sub-auth-key-de-prueba").decode()
NUEVA_SUB_AUTH_KEY = base64.b64encode(b"nueva-sub-auth-key").decode()


def _sesion(user):
    """Cabecera Bearer de un login nuevo: un `sid` propio, como un navegador más."""
    refresh = stamp_session_id(RefreshToken.for_user(user))
    return f"Bearer {refresh.access_token}"


def _sesion_sin_sid(user):
    """Access emitido antes del claim `sid` (transición)."""
    return f"Bearer {AccessToken.for_user(user)}"


def _get(auth, url):
    return Client(raise_request_exception=False).get(url, HTTP_AUTHORIZATION=auth)


def _post(auth, url, body):
    return Client(raise_request_exception=False).post(
        url, data=body, content_type="application/json", HTTP_AUTHORIZATION=auth,
    )


def _desbloquear(auth, vault):
    r = _post(auth, f"/api/vaults/{vault.id}/unlock/", {"sub_auth_key": SUB_AUTH_KEY})
    assert r.status_code == 200, r.content
    return r


def _marcadores():
    return caches["default"].keys("vault_unlocked_*")


@pytest.fixture
def boveda(zk_user):
    vault = Vault.objects.create(
        user=zk_user.user,
        name="Privada",
        is_private=True,
        vault_crypto_version=2,
        sub_kdf_salt="AAECAwQFBgcICQoLDA0ODw==",
        sub_kdf_params=dict(KDF_PARAMS),
        wrapped_vault_subkey="subclave-envuelta",
    )
    vault.set_sub_auth_key(SUB_AUTH_KEY)
    vault.save()
    return vault


@pytest.fixture
def entrada_privada(zk_user, boveda):
    return PasswordEntry.objects.create(
        user=zk_user.user,
        vault=boveda,
        client_id=uuid.uuid4(),
        ciphertext="blob-bajo-la-subclave",
        crypto_version=2,
    )


# --------------------------------------------------------------------------- #
# N9 — el desbloqueo no pasa de una sesión a otra
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n9_el_desbloqueo_de_una_sesion_no_abre_la_boveda_en_otra(zk_user, boveda):
    a, b = _sesion(zk_user.user), _sesion(zk_user.user)
    _desbloquear(a, boveda)

    assert _get(a, f"/api/vaults/{boveda.id}/passwords/").status_code == 200

    r = _get(b, f"/api/vaults/{boveda.id}/passwords/")
    assert r.status_code == 403, (
        f"la sesión B entró en la bóveda que desbloqueó A ({r.status_code}): el marcador "
        "tiene que ser de la sesión, no del usuario (N9)"
    )
    assert r.json().get("code") == "VAULT_LOCKED"


@pytest.mark.django_db
def test_n9_otra_sesion_no_puede_meter_entradas_en_la_boveda(zk_user, boveda):
    a, b = _sesion(zk_user.user), _sesion(zk_user.user)
    _desbloquear(a, boveda)

    r = _post(b, "/api/passwords/add/", {
        "client_id": str(uuid.uuid4()),
        "ciphertext": "blob-bajo-la-clave-principal",
        "crypto_version": 2,
        "vault_id": boveda.id,
    })

    assert r.status_code == 403, r.content
    assert r.json().get("code") == "VAULT_LOCKED"
    assert not PasswordEntry.objects.filter(vault=boveda).exists()


@pytest.mark.django_db
def test_n9_otra_sesion_no_recibe_las_entradas_en_accounts(zk_user, boveda, entrada_privada):
    a, b = _sesion(zk_user.user), _sesion(zk_user.user)
    _desbloquear(a, boveda)

    def ids(auth):
        r = _get(auth, "/api/accounts/")
        assert r.status_code == 200, r.content
        return {e["id"] for e in r.json()["accounts"]}

    assert entrada_privada.id in ids(a)
    assert entrada_privada.id not in ids(b)


@pytest.mark.django_db
def test_n9_token_sin_sid_cae_al_jti_del_access(zk_user, boveda):
    """Transición: un access anterior al claim sólo autoriza su propio desbloqueo. Otro access
    del mismo usuario, también sin `sid`, sigue bloqueado."""
    antiguo, otro_antiguo = _sesion_sin_sid(zk_user.user), _sesion_sin_sid(zk_user.user)
    _desbloquear(antiguo, boveda)

    assert _get(antiguo, f"/api/vaults/{boveda.id}/passwords/").status_code == 200
    assert _get(otro_antiguo, f"/api/vaults/{boveda.id}/passwords/").status_code == 403


@pytest.mark.django_db
def test_n9_el_login_pone_sid_y_sobrevive_a_la_rotacion(zk_user):
    """El `sid` nace en el refresh del login, lo hereda el access y la rotación lo conserva:
    sin eso cada renovación sería una sesión nueva y habría que desbloquear otra vez."""
    client = Client(raise_request_exception=False)
    r = client.post("/auth/login/", data={
        "email": zk_user.credentials["email"],
        "password": zk_user.credentials["password"],
    }, content_type="application/json")
    assert r.status_code == 200, r.content

    refresh = RefreshToken(r.cookies["refresh_token"].value)
    access = AccessToken(r.cookies["access_token"].value)
    sid = refresh.get(SESSION_ID_CLAIM)
    assert sid, "el refresh del login no lleva `sid`"
    assert access.get(SESSION_ID_CLAIM) == sid

    r = client.post("/api/token/refresh/")
    assert r.status_code == 200, r.content
    rotado = RefreshToken(r.cookies["refresh_token"].value)
    assert rotado["jti"] != refresh["jti"], "el refresh no rotó"
    assert rotado.get(SESSION_ID_CLAIM) == sid
    assert AccessToken(r.cookies["access_token"].value).get(SESSION_ID_CLAIM) == sid


# --------------------------------------------------------------------------- #
# N9 — revocar alcanza a todas las sesiones y nunca se salta
# --------------------------------------------------------------------------- #
def _cambiar_contrasena(auth, vault, zk_user):
    return _post(auth, f"/api/vaults/{vault.id}/change-password/", {
        "current_sub_auth_key": SUB_AUTH_KEY,
        "sub_kdf_salt": "Dw4NDAsKCQgHBgUEAwIBAA==",
        "sub_kdf_params": dict(KDF_PARAMS),
        "sub_auth_key": NUEVA_SUB_AUTH_KEY,
        "wrapped_vault_subkey": "subclave-re-envuelta",
    })


def _hacer_publica(auth, vault, zk_user):
    return _post(auth, f"/api/vaults/{vault.id}/convert-privacy/", {
        "make_private": False,
        "current_sub_auth_key": SUB_AUTH_KEY,
        "ciphertexts": {},
    })


def _borrar(auth, vault, zk_user):
    return _post(auth, f"/api/vaults/{vault.id}/delete/", {
        "auth_key": zk_user.material["auth_key_b64"],
    })


REVOCACIONES = pytest.mark.parametrize(
    "operacion", [_cambiar_contrasena, _hacer_publica, _borrar],
    ids=["cambiar-contrasena", "hacer-publica", "borrar"],
)


@pytest.mark.django_db
@REVOCACIONES
def test_n9_revocar_borra_el_desbloqueo_de_todas_las_sesiones(zk_user, boveda, operacion):
    a, b = _sesion(zk_user.user), _sesion(zk_user.user)
    _desbloquear(a, boveda)
    _desbloquear(b, boveda)
    assert len(_marcadores()) == 2

    r = operacion(a, boveda, zk_user)

    assert r.status_code == 200, r.content
    assert _marcadores() == [], "quedó un desbloqueo vivo tras revocar"


@pytest.mark.django_db
@REVOCACIONES
def test_n9_sin_poder_revocar_responde_503_y_no_toca_la_boveda(zk_user, boveda, operacion):
    """Antes el borrado era lenient y llegaba DESPUÉS de guardar: con Redis fallando en ese
    instante, la operación respondía 200 y el marcador viejo seguía autorizando."""
    a = _sesion(zk_user.user)
    _desbloquear(a, boveda)
    antes = Vault.objects.values().get(id=boveda.id)

    error = mock.Mock(side_effect=RedisConnectionError("Redis caído al revocar"))
    with ExitStack() as stack:
        for metodo in ("delete", "delete_pattern"):
            stack.enter_context(mock.patch.object(caches["default"], metodo, error))
        r = operacion(a, boveda, zk_user)

    assert r.status_code == 503, r.content
    assert Vault.objects.values().get(id=boveda.id) == antes


# --------------------------------------------------------------------------- #
# N9 — el marcador se renueva con el uso
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n9_usar_la_boveda_renueva_el_marcador(zk_user, boveda):
    a = _sesion(zk_user.user)
    _desbloquear(a, boveda)
    cache = caches["default"]
    (clave,) = _marcadores()
    cache.touch(clave, 30)  # como si hubieran pasado 14,5 min desde el desbloqueo

    assert _get(a, f"/api/vaults/{boveda.id}/passwords/").status_code == 200

    assert cache.ttl(clave) > VAULT_UNLOCK_TTL_SECONDS - 60, (
        f"TTL {cache.ttl(clave)} s tras usar la bóveda: el marcador no se renovó (N9)"
    )
