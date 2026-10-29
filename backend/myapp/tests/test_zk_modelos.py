"""L1 — modelos zero-knowledge y esquema purgado.

Cubre (§4.1/§4.2/§4.4 del PLAN-DE-PRUEBAS.md), todo por ORM y con las fixtures del
conftest de la tanda 6 (zk_user, build_user_crypto_material):

  - Z5  UserCrypto no reconstruye la MK: sólo guarda auth_key_hash (Argon2) y
        wrapped_vault_key; verify_auth_key verifica sin reconstruir.
  - Z6  Sal por usuario: dos UserCrypto nuevos tienen kdf_salt distintos aun con la
        MISMA contraseña maestra (sustituye a C2-b, ya no hay sal global).
  - Z8  Anti-swap: PasswordEntry.client_id es `unique` → IntegrityError al duplicar.
  - Z12 Vault.verify_sub_auth_key: False si no es privada o no tiene hash; True sólo
        con la SubAuthKey correcta.
  - C1  myapp.models NO exporta MasterKey (purgado en la migración 0025).
  - C2  El esquema no tiene passwordentry.salt ni la tabla masterkey.
  - M11 verify_auth_key / verify_sub_auth_key delegan en check_password (tiempo
        constante); se comprueba espiando check_password.

Ninguno es xfail: con las Fases 0-2 cerradas todos deben pasar hoy (§3).
"""

import base64
import os
import uuid

import pytest
from django.apps import apps
from django.db import IntegrityError, connection, transaction

from myapp.models import PasswordEntry, UserCrypto, Vault
from myapp.tests.conftest import TEST_MASTER_PASSWORD, build_user_crypto_material

pytestmark = pytest.mark.l1


def _random_sub_auth_b64() -> str:
    """Una SubAuthKey de prueba en base64 (32 bytes), como la derivaría el cliente."""
    return base64.b64encode(os.urandom(32)).decode()


# --------------------------------------------------------------------------- #
# C1 — MasterKey no existe (purgado en 0025)
# --------------------------------------------------------------------------- #
def test_c1_myapp_models_no_exporta_masterkey():
    import myapp.models as models_mod

    assert not hasattr(models_mod, "MasterKey"), (
        "MasterKey era el fallo raíz C1/C2 y se purgó en la migración 0025; "
        "myapp.models no debe volver a exportarlo."
    )
    assert "masterkey" not in apps.all_models["myapp"], (
        "MasterKey no debe estar registrado como modelo de la app."
    )


# --------------------------------------------------------------------------- #
# C2 — el esquema no conserva ni salt ni la tabla masterkey
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_c2_esquema_sin_salt_ni_tabla_masterkey():
    # La tabla de MasterKey no existe (DeleteModel en 0025): sin ella no hay
    # masterkey.salt (la sal global que C2 señalaba) de ningún tipo.
    assert "myapp_masterkey" not in connection.introspection.table_names(), (
        "La tabla myapp_masterkey debía desaparecer con DeleteModel en 0025."
    )

    # PasswordEntry no tiene la columna `salt` (RemoveField en 0025).
    with connection.cursor() as cursor:
        cols = {
            c.name
            for c in connection.introspection.get_table_description(
                cursor, "myapp_passwordentry"
            )
        }
    assert "salt" not in cols, (
        f"passwordentry.salt debía purgarse en 0025; columnas actuales: {sorted(cols)}"
    )

    # Y el modelo tampoco lo expone.
    pe_fields = {f.name for f in PasswordEntry._meta.get_fields()}
    assert "salt" not in pe_fields


# --------------------------------------------------------------------------- #
# Z5 — UserCrypto no reconstruye la Master Key
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_z5_usercrypto_no_reconstruye_master_key(zk_user):
    field_names = {f.name for f in UserCrypto._meta.get_fields()}

    # No hay ningún campo que guarde la maestra, la MK, la EncKey ni la VaultKey.
    prohibidos = {
        "master_key", "master_password", "masterkey", "mk",
        "enc_key", "encryption_key", "vault_key", "plaintext", "password",
    }
    fuga = field_names & prohibidos
    assert not fuga, f"UserCrypto no debe guardar secretos derivables de la maestra: {fuga}"

    # Sólo material opaco.
    assert {"auth_key_hash", "wrapped_vault_key", "kdf_salt"} <= field_names

    # auth_key_hash es un hash de contraseña (Argon2 primero, paso 14), NO la AuthKey
    # en claro: no permite reconstruir nada.
    assert zk_user.crypto.auth_key_hash.startswith("argon2"), (
        f"Se esperaba un hash Argon2, no {zk_user.crypto.auth_key_hash[:16]!r}"
    )
    assert zk_user.material["auth_key_b64"] not in zk_user.crypto.auth_key_hash

    # verify_auth_key: True con la buena, False con otra. Verifica, no reconstruye.
    assert zk_user.crypto.verify_auth_key(zk_user.material["auth_key_b64"]) is True
    assert zk_user.crypto.verify_auth_key(_random_sub_auth_b64()) is False


# --------------------------------------------------------------------------- #
# Z6 — sal KDF por usuario (no global)
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_z6_sal_kdf_por_usuario_distinta(zk_user, django_user_model):
    u2 = django_user_model.objects.create_user(
        username="zk_tester_beta",
        email="zk_tester_beta@example.test",
        password="Wren$Kilo7pluto",
    )
    # MISMA contraseña maestra a propósito: aun así la sal debe diferir.
    mat2 = build_user_crypto_material(TEST_MASTER_PASSWORD)
    c2 = UserCrypto(
        user=u2,
        kdf_salt=mat2["kdf_salt"],
        kdf_params=mat2["kdf_params"],
        wrapped_vault_key=mat2["wrapped_vault_key"],
        crypto_version=UserCrypto.CURRENT_CRYPTO_VERSION,
    )
    c2.set_auth_key(mat2["auth_key_b64"])
    c2.save()

    assert zk_user.crypto.kdf_salt != c2.kdf_salt, (
        "kdf_salt debe ser por-usuario (aleatoria), no una sal global compartida."
    )


# --------------------------------------------------------------------------- #
# Z8 — anti-swap: client_id único
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_z8_client_id_unico_anti_swap(zk_user):
    cid = uuid.uuid4()
    PasswordEntry.objects.create(user=zk_user.user, ciphertext="blob-A", client_id=cid)

    # Un atacante con escritura en BD que copie ciphertext+client_id de otra fila
    # choca con la restricción UNIQUE: no puede reubicar un blob bajo otra identidad.
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            PasswordEntry.objects.create(
                user=zk_user.user, ciphertext="blob-B", client_id=cid
            )


# --------------------------------------------------------------------------- #
# Z12 — Vault.verify_sub_auth_key espeja a UserCrypto
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_z12_verify_sub_auth_key_semantica(zk_user):
    sub_good = _random_sub_auth_b64()
    sub_bad = _random_sub_auth_b64()

    # Bóveda NO privada: False aunque tuviera hash (el guardián corta antes).
    v_public = Vault.objects.create(user=zk_user.user, name="pub", is_private=False)
    v_public.set_sub_auth_key(sub_good)
    v_public.save()
    assert v_public.verify_sub_auth_key(sub_good) is False

    # Bóveda privada SIN hash: False.
    v_priv_nohash = Vault.objects.create(
        user=zk_user.user, name="priv_nohash", is_private=True
    )
    assert v_priv_nohash.verify_sub_auth_key(sub_good) is False

    # Bóveda privada CON hash: True sólo con la SubAuthKey correcta.
    v_priv = Vault.objects.create(user=zk_user.user, name="priv", is_private=True)
    v_priv.set_sub_auth_key(sub_good)
    v_priv.save()
    assert v_priv.verify_sub_auth_key(sub_good) is True
    assert v_priv.verify_sub_auth_key(sub_bad) is False


# --------------------------------------------------------------------------- #
# M11 — verify_* usan check_password (tiempo constante)
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_m11_verify_delegan_en_check_password(zk_user, monkeypatch):
    import myapp.models as models_mod

    real_check = models_mod.check_password
    calls = []

    def spy(raw, encoded, setter=None, preferred="default"):
        calls.append((raw, encoded))
        return real_check(raw, encoded, setter, preferred)

    monkeypatch.setattr(models_mod, "check_password", spy)

    # UserCrypto.verify_auth_key delega en check_password.
    zk_user.crypto.verify_auth_key(zk_user.material["auth_key_b64"])
    assert calls, "verify_auth_key debe delegar en check_password (Argon2, tiempo constante)."

    calls.clear()

    # Vault.verify_sub_auth_key (privada con hash) también delega en check_password.
    sub = _random_sub_auth_b64()
    v = Vault.objects.create(user=zk_user.user, name="m11", is_private=True)
    v.set_sub_auth_key(sub)
    v.save()
    v.verify_sub_auth_key(sub)
    assert calls, "verify_sub_auth_key debe delegar en check_password (tiempo constante)."
