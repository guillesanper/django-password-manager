"""L1 — el desbloqueo de una bóveda privada es por sesión de login (N9).

Cada petición atraviesa la cadena REAL con `Client`. Las dos "sesiones" de un mismo usuario
son dos logins distintos: cada uno con su refresh y su claim `sid`, que es lo que ve el
servidor cuando el usuario abre la app en dos navegadores.

  - N9-a  El login y el registro emiten un `sid` en el refresh; el access lo hereda y la
          rotación del refresh lo conserva.
  - N9-b  Desbloquear la bóveda en la sesión A no la desbloquea en la B: B no puede añadir
          entradas ni ver las existentes. Antes el marcador era por usuario y B sí podía.
  - N9-c  Invalidar el desbloqueo (cambio de contraseña, conversión, borrado) lo quita en
          todas las sesiones.
  - N9-d  (AU-31) Cada comprobación que pasa renueva el TTL del marcador.
  - N9-e  Un token anterior al cambio, sin `sid`, se aísla por el `jti` de su access.

La otra mitad de N9, que el cliente no cifre para una bóveda privada con la clave principal,
la cubre `frontend/src/services/cryptoSession.test.ts` (L3).
"""

import base64
import json
import os
import uuid

import pytest
from django.conf import settings
from django.core.cache import cache
from django.test import Client
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from myapp.models import PasswordEntry, Vault
from myapp.utils.login_session import SESSION_CLAIM
from myapp.utils.vault_unlock import VAULT_UNLOCK_TTL_SECONDS, clear_vault_unlock

pytestmark = pytest.mark.l1


def _sesion(user):
    """Cabecera Bearer de un login nuevo (refresh propio con su `sid`), como hace el login."""
    refresh = RefreshToken.for_user(user)
    refresh[SESSION_CLAIM] = uuid.uuid4().hex
    return f"Bearer {refresh.access_token}"


def _post(auth, path, body):
    return Client(raise_request_exception=False).post(
        path, data=body, content_type="application/json", HTTP_AUTHORIZATION=auth,
    )


def _get(auth, path):
    return Client(raise_request_exception=False).get(path, HTTP_AUTHORIZATION=auth)


@pytest.fixture
def boveda(zk_user):
    """Bóveda privada v2 con una SubAuthKey conocida (la que derivaría el cliente)."""
    sub_auth_key = base64.b64encode(os.urandom(32)).decode()
    vault = Vault(
        user=zk_user.user, name="Privada", is_private=True, vault_crypto_version=2,
        sub_kdf_salt=base64.b64encode(os.urandom(16)).decode(),
        sub_kdf_params={"algo": "argon2id"}, wrapped_vault_subkey="opaca",
    )
    vault.set_sub_auth_key(sub_auth_key)
    vault.save()
    vault.sub_auth_key = sub_auth_key
    return vault


def _desbloquear(auth, vault):
    r = _post(auth, f"/api/vaults/{vault.id}/unlock/", {"sub_auth_key": vault.sub_auth_key})
    assert r.status_code == 200, r.content


def _anadir(auth, vault):
    return _post(auth, "/api/passwords/add/", {
        "client_id": str(uuid.uuid4()),
        "ciphertext": "blob",
        "crypto_version": 2,
        "vault_id": vault.id,
    })


# --------------------------------------------------------------------------- #
# N9-a — el `sid` nace en el login y sobrevive a la rotación
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n9a_login_emite_sid_que_hereda_el_access_y_conserva_la_rotacion(zk_user):
    client = Client()
    r = client.post(
        "/auth/login/",
        data={"email": zk_user.credentials["email"], "password": zk_user.credentials["password"]},
        content_type="application/json",
    )
    assert r.status_code == 200, r.content

    refresh = RefreshToken(r.cookies[settings.JWT_AUTH_REFRESH_COOKIE].value)
    access = AccessToken(r.cookies[settings.JWT_AUTH_COOKIE].value)
    sid = refresh.get(SESSION_CLAIM)
    assert sid, "el refresh del login debe llevar el sid de la sesión"
    assert access.get(SESSION_CLAIM) == sid

    r = client.post("/api/token/refresh/")
    assert r.status_code == 200, r.content
    rotated = RefreshToken(r.cookies[settings.JWT_AUTH_REFRESH_COOKIE].value)
    assert rotated["jti"] != refresh["jti"], "con ROTATE_REFRESH_TOKENS el refresh es nuevo"
    assert rotated.get(SESSION_CLAIM) == sid
    assert AccessToken(r.cookies[settings.JWT_AUTH_COOKIE].value).get(SESSION_CLAIM) == sid


@pytest.mark.django_db
def test_n9a_dos_logins_tienen_sid_distinto(zk_user):
    body = {"email": zk_user.credentials["email"], "password": zk_user.credentials["password"]}
    sids = set()
    for _ in range(2):
        r = Client().post("/auth/login/", data=body, content_type="application/json")
        assert r.status_code == 200, r.content
        sids.add(RefreshToken(r.cookies[settings.JWT_AUTH_REFRESH_COOKIE].value)[SESSION_CLAIM])
    assert len(sids) == 2


# --------------------------------------------------------------------------- #
# N9-b — el desbloqueo no se comparte entre sesiones
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n9b_desbloquear_en_una_sesion_no_abre_la_boveda_en_otra(zk_user, boveda):
    sesion_a, sesion_b = _sesion(zk_user.user), _sesion(zk_user.user)
    _desbloquear(sesion_a, boveda)

    r = _anadir(sesion_b, boveda)
    assert r.status_code == 403, r.content
    assert json.loads(r.content)["code"] == "VAULT_LOCKED"
    assert not PasswordEntry.objects.filter(vault=boveda).exists()

    assert _anadir(sesion_a, boveda).status_code == 200


@pytest.mark.django_db
def test_n9b_otra_sesion_no_ve_las_entradas_de_la_boveda(zk_user, boveda):
    sesion_a, sesion_b = _sesion(zk_user.user), _sesion(zk_user.user)
    _desbloquear(sesion_a, boveda)
    assert _anadir(sesion_a, boveda).status_code == 200

    def vault_ids(auth):
        r = _get(auth, "/api/accounts/")
        assert r.status_code == 200, r.content
        return [e["vault_id"] for e in json.loads(r.content)["accounts"]]

    assert vault_ids(sesion_a) == [boveda.id]
    assert vault_ids(sesion_b) == []
    assert _get(sesion_b, f"/api/vaults/{boveda.id}/passwords/").status_code == 403


# --------------------------------------------------------------------------- #
# N9-c — invalidar el desbloqueo lo quita en todas las sesiones
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n9c_invalidar_quita_el_desbloqueo_de_todas_las_sesiones(zk_user, boveda):
    sesiones = [_sesion(zk_user.user), _sesion(zk_user.user)]
    for auth in sesiones:
        _desbloquear(auth, boveda)
        assert _anadir(auth, boveda).status_code == 200

    clear_vault_unlock(zk_user.user.id, boveda.id)

    for auth in sesiones:
        assert _anadir(auth, boveda).status_code == 403


@pytest.mark.django_db
def test_n9c_invalidar_una_boveda_no_toca_las_demas(zk_user, boveda):
    otra = Vault.objects.get(pk=boveda.pk)
    otra.pk, otra.name = None, "Otra"
    otra.save()
    otra.sub_auth_key = boveda.sub_auth_key
    auth = _sesion(zk_user.user)
    _desbloquear(auth, boveda)
    _desbloquear(auth, otra)

    clear_vault_unlock(zk_user.user.id, boveda.id)

    assert _anadir(auth, boveda).status_code == 403
    assert _anadir(auth, otra).status_code == 200


# --------------------------------------------------------------------------- #
# N9-d (AU-31) — el marcador caduca por inactividad, no a los 15 min del desbloqueo
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n9d_usar_la_boveda_renueva_el_marcador(zk_user, boveda):
    auth = _sesion(zk_user.user)
    _desbloquear(auth, boveda)
    (key,) = cache.keys(f"vault_unlocked_{zk_user.user.id}_{boveda.id}_*")
    cache.touch(key, 30)  # como si hubieran pasado 14,5 min desde el desbloqueo

    assert _anadir(auth, boveda).status_code == 200

    assert cache.ttl(key) > VAULT_UNLOCK_TTL_SECONDS - 30


# --------------------------------------------------------------------------- #
# N9-e — transición: un token sin `sid` se aísla por el `jti` de su access
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n9e_token_sin_sid_no_comparte_desbloqueo(zk_user, boveda):
    antiguo = f"Bearer {RefreshToken.for_user(zk_user.user).access_token}"
    otro_antiguo = f"Bearer {RefreshToken.for_user(zk_user.user).access_token}"
    _desbloquear(antiguo, boveda)

    assert _anadir(antiguo, boveda).status_code == 200
    assert _anadir(otro_antiguo, boveda).status_code == 403
