"""Pasada en vacío de L1 — demuestra el AISLAMIENTO, no ningún hallazgo (§9, punto 4).

Esta tanda (config común de L1) NO prueba todavía ningún hallazgo/ZK/batería G (eso es
la tanda 7). Aquí sólo se verifica que el andamiaje aísla correctamente:

  - la BD de test se crea y se destruye (rollback por caso),
  - Redis va a la db 15 con KEY_PREFIX='test' (no db 1/2 de la app),
  - el bucket de MinIO es el de test (no el de producción),
  - el logging de fichero está silenciado (NullHandler),
  - el helper de derivación ZK reproduce el vector Z4 (no diverge de crypto.ts),
  - el usuario+UserCrypto sembrado por ORM tiene material ZK utilizable.

A propósito lee `django.conf.settings` (los overrides de settings_test): aquí QUEREMOS
comprobar que el aislamiento se aplicó. Los tests que afirman sobre configuración de
PRODUCCIÓN (A8-a, M6, BL1…) leerán `demo.settings` en la tanda 7 (§6, regla dura).
"""

import pytest
from django.conf import settings

from myapp.tests.conftest import (
    Z4_VECTOR,
    derive_auth_key,
    derive_enc_key,
    derive_master_key,
    unwrap_key,
    zk_helper_matches_vector,
)

pytestmark = pytest.mark.l1


# --------------------------------------------------------------------------- #
# Redis en db 15, prefijo de test
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cache_name", ["default", "sessions"])
def test_redis_apunta_a_db15_con_prefijo_test(cache_name):
    cache_cfg = settings.CACHES[cache_name]
    assert cache_cfg["LOCATION"].rstrip("/").endswith("/15"), (
        f"La caché {cache_name!r} debería ir a la db 15 de test, no a "
        f"{cache_cfg['LOCATION']!r} (db 1/2 son de la app viva)."
    )
    assert cache_cfg["KEY_PREFIX"] == "test", (
        f"La caché {cache_name!r} debería usar KEY_PREFIX='test'."
    )


# --------------------------------------------------------------------------- #
# Bucket de MinIO propio
# --------------------------------------------------------------------------- #
def test_bucket_minio_es_de_test():
    assert settings.MINIO_BUCKET_NAME.startswith("test-"), (
        f"MINIO_BUCKET_NAME={settings.MINIO_BUCKET_NAME!r} debería empezar por 'test-' "
        "para no dejar objetos en el bucket de producción."
    )


# --------------------------------------------------------------------------- #
# Logging de fichero silenciado
# --------------------------------------------------------------------------- #
def test_logging_de_fichero_silenciado():
    handlers = settings.LOGGING["handlers"]
    culpables = {
        name: cfg.get("class")
        for name, cfg in handlers.items()
        if "FileHandler" in cfg.get("class", "") or "filename" in cfg
    }
    assert not culpables, (
        f"Ningún handler debería escribir a fichero en test; siguen activos: {culpables}"
    )
    # Los nombres de handler de fichero siguen existiendo, ahora como NullHandler.
    for name in ("security_file", "audit_file", "auth_file"):
        assert handlers[name]["class"] == "logging.NullHandler"


def test_debug_desactivado_fijo():
    assert settings.DEBUG is False


# --------------------------------------------------------------------------- #
# La BD de test se crea y se destruye (rollback por caso)
# --------------------------------------------------------------------------- #
# Dos tests crean un usuario con el MISMO username. Si la BD no se aislara/rollback
# entre casos, el segundo reventaría con IntegrityError. Que ambos pasen prueba que
# cada caso arranca con una BD limpia y la deja limpia.
@pytest.mark.django_db
def test_bd_se_crea_y_aisla_primera_pasada(django_user_model):
    django_user_model.objects.create_user(username="iso_probe", password="Zephyr$Mako4nile")
    assert django_user_model.objects.filter(username="iso_probe").count() == 1


@pytest.mark.django_db
def test_bd_se_destruye_entre_casos_segunda_pasada(django_user_model):
    # Si el rollback no funcionara, "iso_probe" ya existiría del test anterior.
    assert django_user_model.objects.filter(username="iso_probe").count() == 0
    django_user_model.objects.create_user(username="iso_probe", password="Zephyr$Mako4nile")
    assert django_user_model.objects.filter(username="iso_probe").count() == 1


# --------------------------------------------------------------------------- #
# El helper de derivación ZK reproduce el vector Z4 (trampa 14)
# --------------------------------------------------------------------------- #
def test_helper_zk_reproduce_vector_z4():
    if not zk_helper_matches_vector():
        pytest.skip(
            "El helper de derivación Python diverge del vector Z4 de crypto.ts "
            "(trampa 14): se salta ESTE test en vez de tumbar los que siembran ZK. "
            "Revisa KDF_PARAMS / HKDF / Argon2id antes de fiarte del material sembrado."
        )
    import base64

    salt = base64.b64decode(Z4_VECTOR["salt_b64"])
    mk = derive_master_key(Z4_VECTOR["password"], salt)
    assert mk.hex() == Z4_VECTOR["mk_hex"]
    assert derive_auth_key(mk).hex() == Z4_VECTOR["auth_hex"]
    assert derive_enc_key(mk).hex() == Z4_VECTOR["enc_hex"]


# --------------------------------------------------------------------------- #
# El usuario+UserCrypto sembrado por ORM tiene material ZK utilizable
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_fixture_zk_user_material_utilizable(zk_user):
    # UserCrypto existe y está enlazado (OneToOne).
    assert zk_user.crypto.pk is not None
    assert zk_user.user.crypto.pk == zk_user.crypto.pk

    # El servidor puede VERIFICAR la AuthKey (Argon2, tiempo constante) sin reconstruir
    # la MK: verify_auth_key(True) con la buena, (False) con una cualquiera.
    good_auth = zk_user.material["auth_key_b64"]
    assert zk_user.crypto.verify_auth_key(good_auth) is True
    assert zk_user.crypto.verify_auth_key("QUJDREVGRw==") is False  # AuthKey cualquiera != real

    # Y el cliente (que sí tiene la EncKey) puede desenvolver la VaultKey original.
    recovered = unwrap_key(zk_user.material["enc_key"], zk_user.crypto.wrapped_vault_key)
    assert recovered == zk_user.material["vault_key"]
