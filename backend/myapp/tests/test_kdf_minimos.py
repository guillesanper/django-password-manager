"""L1 — mínimos de los parámetros KDF en el servidor (N13, AU-09).

El cliente deriva la maestra y la contraseña de cada bóveda privada con los `kdf_params` que
le da el servidor, y las cinco vistas que los reciben (setup y rotación de la maestra; crear,
cambiar la contraseña y convertir a privada una bóveda) guardaban cualquier dict. Con unos
parámetros baratos, la AuthKey o la SubAuthKey que el cliente manda después se rompen offline.

Aquí se fija que esas vistas responden 400 `KDF_PARAMS_INVALID` y no tocan la BD con unos
parámetros por debajo de `KDF_PARAMS`, incompletos o de otro tipo, y que los de `KDF_PARAMS`
siguen pasando. La otra mitad, que el cliente se niega a derivar con ellos aunque se los dé el
servidor, la cubre `frontend/src/services/crypto.test.ts` (L3).
"""

import base64
import os

import pytest
from django.test import Client
from rest_framework_simplejwt.tokens import AccessToken

from myapp.models import UserCrypto, Vault
from myapp.tests.conftest import (
    KDF_PARAMS,
    TEST_MASTER_PASSWORD,
    build_user_crypto_material,
)

pytestmark = pytest.mark.l1

# El ataque de AU-09 y las variantes que un servidor descuidado también aceptaría.
PARAMS_INVALIDOS = {
    "baratos": {**KDF_PARAMS, "m": 8, "t": 1, "p": 1},
    "memoria_baja": {**KDF_PARAMS, "m": 65535},
    "pocas_iteraciones": {**KDF_PARAMS, "t": 2},
    "sin_paralelismo": {**KDF_PARAMS, "p": 0},
    "otro_algoritmo": {**KDF_PARAMS, "algo": "argon2i"},
    "hash_corto": {**KDF_PARAMS, "hashLen": 16},
    "version_antigua": {**KDF_PARAMS, "version": 16},
    "memoria_como_texto": {**KDF_PARAMS, "m": "65536"},
    "booleano": {**KDF_PARAMS, "p": True},
    "incompletos": {"algo": "argon2id", "m": 65536, "t": 3, "p": 4},
    "vacios": {},
    "ausentes": None,
}


def _post(user, url, body):
    return Client(raise_request_exception=False).post(
        url,
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {AccessToken.for_user(user)}",
    )


def _assert_rechazo(r):
    assert r.status_code == 400, r.content
    assert r.json()["code"] == "KDF_PARAMS_INVALID"


def _sub_material(params):
    return {
        "sub_kdf_salt": base64.b64encode(os.urandom(16)).decode(),
        "sub_kdf_params": params,
        "sub_auth_key": base64.b64encode(os.urandom(32)).decode(),
        "wrapped_vault_subkey": "subclave-envuelta",
    }


@pytest.fixture
def usuario_sin_maestra(db, django_user_model):
    return django_user_model.objects.create_user(
        username="kdf_sin_maestra", email="kdf_sin_maestra@example.test", password="x",
    )


@pytest.fixture
def boveda_privada(zk_user):
    vault = Vault.objects.create(
        user=zk_user.user, name="Privada", is_private=True, vault_crypto_version=2,
        sub_kdf_salt="AAECAwQFBgcICQoLDA0ODw==", sub_kdf_params=dict(KDF_PARAMS),
        wrapped_vault_subkey="subclave-envuelta",
    )
    vault.set_sub_auth_key(base64.b64encode(b"\x01" * 32).decode())
    vault.save()
    return vault


def _setup(user, params):
    material = build_user_crypto_material(TEST_MASTER_PASSWORD)
    return _post(user, "/api/master-key/setup/", {
        "kdf_salt": material["kdf_salt"],
        "kdf_params": params,
        "auth_key": material["auth_key_b64"],
        "wrapped_vault_key": material["wrapped_vault_key"],
        "crypto_version": 2,
    })


def _cambiar_maestra(zk_user, params):
    nuevo = build_user_crypto_material(TEST_MASTER_PASSWORD + "-nueva")
    return _post(zk_user.user, "/api/master-key/change/", {
        "current_auth_key": zk_user.material["auth_key_b64"],
        "kdf_salt": nuevo["kdf_salt"],
        "kdf_params": params,
        "auth_key": nuevo["auth_key_b64"],
        "wrapped_vault_key": nuevo["wrapped_vault_key"],
    })


# --------------------------------------------------------------------------- #
# Clave maestra
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
@pytest.mark.parametrize("params", PARAMS_INVALIDOS.values(), ids=PARAMS_INVALIDOS.keys())
def test_n13_setup_rechaza_kdf_por_debajo_del_minimo(usuario_sin_maestra, params):
    _assert_rechazo(_setup(usuario_sin_maestra, params))
    assert not UserCrypto.objects.filter(user=usuario_sin_maestra).exists()


@pytest.mark.django_db
def test_n13_setup_acepta_kdf_params(usuario_sin_maestra):
    r = _setup(usuario_sin_maestra, dict(KDF_PARAMS))
    assert r.status_code == 200, r.content
    assert UserCrypto.objects.get(user=usuario_sin_maestra).kdf_params == KDF_PARAMS


@pytest.mark.django_db
@pytest.mark.parametrize("params", PARAMS_INVALIDOS.values(), ids=PARAMS_INVALIDOS.keys())
def test_n13_cambiar_maestra_rechaza_kdf_por_debajo_del_minimo(zk_user, params):
    antes = UserCrypto.objects.get(user=zk_user.user)
    _assert_rechazo(_cambiar_maestra(zk_user, params))
    despues = UserCrypto.objects.get(user=zk_user.user)
    assert (despues.kdf_salt, despues.kdf_params, despues.auth_key_hash) == (
        antes.kdf_salt, antes.kdf_params, antes.auth_key_hash,
    )


@pytest.mark.django_db
def test_n13_cambiar_maestra_acepta_kdf_params(zk_user):
    r = _cambiar_maestra(zk_user, dict(KDF_PARAMS))
    assert r.status_code == 200, r.content


# --------------------------------------------------------------------------- #
# Bóvedas privadas
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
@pytest.mark.parametrize("params", PARAMS_INVALIDOS.values(), ids=PARAMS_INVALIDOS.keys())
def test_n13_crear_boveda_privada_rechaza_kdf_por_debajo_del_minimo(zk_user, params):
    r = _post(zk_user.user, "/api/vaults/create/", {
        "name": "Nueva privada", "color": "blue", "is_private": True, **_sub_material(params),
    })
    _assert_rechazo(r)
    assert not Vault.objects.filter(user=zk_user.user, name="Nueva privada").exists()


@pytest.mark.django_db
def test_n13_crear_boveda_privada_acepta_kdf_params(zk_user):
    r = _post(zk_user.user, "/api/vaults/create/", {
        "name": "Nueva privada", "color": "blue", "is_private": True,
        **_sub_material(dict(KDF_PARAMS)),
    })
    assert r.status_code == 200, r.content
    assert Vault.objects.get(user=zk_user.user, name="Nueva privada").sub_kdf_params == KDF_PARAMS


@pytest.mark.django_db
@pytest.mark.parametrize("params", PARAMS_INVALIDOS.values(), ids=PARAMS_INVALIDOS.keys())
def test_n13_cambiar_contrasena_de_boveda_rechaza_kdf_por_debajo_del_minimo(
    zk_user, boveda_privada, params,
):
    r = _post(zk_user.user, f"/api/vaults/{boveda_privada.id}/change-password/", {
        "current_sub_auth_key": base64.b64encode(b"\x01" * 32).decode(), **_sub_material(params),
    })
    _assert_rechazo(r)
    boveda_privada.refresh_from_db()
    assert boveda_privada.sub_kdf_params == KDF_PARAMS
    assert boveda_privada.wrapped_vault_subkey == "subclave-envuelta"


@pytest.mark.django_db
@pytest.mark.parametrize("params", PARAMS_INVALIDOS.values(), ids=PARAMS_INVALIDOS.keys())
def test_n13_convertir_en_privada_rechaza_kdf_por_debajo_del_minimo(zk_user, params):
    vault = Vault.objects.create(user=zk_user.user, name="Pública")
    r = _post(zk_user.user, f"/api/vaults/{vault.id}/convert-privacy/", {
        "make_private": True, "ciphertexts": {}, **_sub_material(params),
    })
    _assert_rechazo(r)
    vault.refresh_from_db()
    assert not vault.is_private
    assert vault.sub_kdf_params == {}
