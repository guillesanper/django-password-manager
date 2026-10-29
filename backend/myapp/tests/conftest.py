"""Infraestructura compartida de L1 (dentro del contenedor `web`).

Contiene, según §6 del PLAN-DE-PRUEBAS.md:

  - Aislamiento entre casos: fixture `autouse` que limpia `default` y `sessions`
    ANTES y DESPUÉS de cada test (trampa 10).
  - Chequeos previos: Redis alcanzable (aborta pronto y claro si no); nota sobre el
    permiso de crear la BD de test.
  - El HELPER de derivación ZK en Python que reproduce `crypto.ts` (Argon2id + HKDF),
    anclado al VECTOR Z4 compartido con el test de vitest (trampa 14).
  - Fixture de usuario + UserCrypto sembrado por ORM con material ZK real.

Nada de esto se importa en el host: L1 vive en el contenedor (§2.1).

⚠️ Si `pytest` aborta al CREAR la base de datos de test ("permission denied to create
database"), el usuario de la BD no es superusuario. `myuser` lo es por el initdb, pero
si se cambió, reejecuta con la BD ya existente:

    docker compose exec web pytest myapp/tests --reuse-db
    docker compose exec web pytest myapp/tests --create-db   # para forzar recreación
"""

import base64
import os

import pytest
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# =========================================================================== #
# Helper de derivación zero-knowledge (espejo de frontend/src/services/crypto.ts)
# =========================================================================== #
# crypto.ts:
#   MK      = argon2id(pwd, salt, m=65536 KiB, t=3, p=4, hashLen=32, v=0x13)  [hash-wasm]
#   AuthKey = HKDF-SHA256(ikm=MK, salt="", info="auth", L=32)
#   EncKey  = HKDF-SHA256(ikm=MK, salt="", info="enc",  L=32)
#   wrapped_vault_key = base64( nonce(12) || AES-256-GCM(EncKey, VaultKey) )   sin AAD
#
# En Python la reproducimos con argon2-cffi (Type.ID, version=19) y cryptography
# (HKDF con salt vacío == new Uint8Array(0) de WebCrypto; AES-GCM con AAD None).

KDF_PARAMS = {
    "algo": "argon2id",
    "m": 65536,   # 64 MiB (KiB)
    "t": 3,
    "p": 4,
    "hashLen": 32,
    "version": 19,  # Argon2 v1.3 (0x13)
}


def derive_master_key(master_password: str, salt: bytes, params: dict = KDF_PARAMS) -> bytes:
    """MK = Argon2id(master_password, salt). Devuelve 32 bytes crudos (== deriveMasterKey)."""
    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=params["t"],
        memory_cost=params["m"],
        parallelism=params["p"],
        hash_len=params["hashLen"],
        type=Type.ID,
        version=params["version"],
    )


def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 con sal VACÍA (la MK ya es de alta entropía). Igual que crypto.ts."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=b"", info=info).derive(ikm)


def derive_auth_key(mk: bytes) -> bytes:
    """AuthKey = HKDF(MK, "auth"). Se guarda su Argon2id en UserCrypto.auth_key_hash."""
    return _hkdf(mk, b"auth")


def derive_enc_key(mk: bytes) -> bytes:
    """EncKey = HKDF(MK, "enc"). Nunca sale del navegador; envuelve la VaultKey."""
    return _hkdf(mk, b"enc")


def wrap_key(enc_key: bytes, key_raw: bytes) -> str:
    """base64( nonce(12) || AES-256-GCM(enc_key, key_raw) ), sin AAD (== wrapVaultKey)."""
    nonce = os.urandom(12)
    ct = AESGCM(enc_key).encrypt(nonce, key_raw, None)
    return base64.b64encode(nonce + ct).decode()


def unwrap_key(enc_key: bytes, wrapped_b64: str) -> bytes:
    """Inversa de wrap_key. Lanza si la clave o el tag no casan (== unwrapVaultKey)."""
    blob = base64.b64decode(wrapped_b64)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(enc_key).decrypt(nonce, ct, None)


# --- Vector Z4 (compartido con crypto.test.ts; validado en TS el 25 jul) ----
Z4_VECTOR = {
    "password": "correct horse battery staple",
    "salt_b64": "AAECAwQFBgcICQoLDA0ODw==",  # 16 bytes 0x00..0x0f
    "mk_hex": "853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e",
    "auth_hex": "8a0730bfd3e742930ccc9e42cc2fedc203a56f0f118f6c7776ac7b984b7f8ae0",
    "enc_hex": "aae74ab4049d24620c02a210afd208ec0350e12d4c7bf0697474479eaad63902",
}


def zk_helper_matches_vector() -> bool:
    """True si el helper Python reproduce el vector Z4 (no diverge de crypto.ts).

    Se usa como CANARIO (trampa 14): si un día Python y TS divergen, el test del
    vector se SALTA con un motivo claro en vez de tumbar 20 tests que siembran
    UserCrypto por ORM (esos siguen siendo internamente consistentes en Python)."""
    try:
        salt = base64.b64decode(Z4_VECTOR["salt_b64"])
        mk = derive_master_key(Z4_VECTOR["password"], salt)
        return (
            mk.hex() == Z4_VECTOR["mk_hex"]
            and derive_auth_key(mk).hex() == Z4_VECTOR["auth_hex"]
            and derive_enc_key(mk).hex() == Z4_VECTOR["enc_hex"]
        )
    except Exception:
        return False


def build_user_crypto_material(master_password: str, params: dict = KDF_PARAMS) -> dict:
    """Genera el material ZK de un usuario nuevo (== setupUserCrypto de crypto.ts).

    Devuelve lo enviable al servidor (kdf_salt, kdf_params, auth_key_b64,
    wrapped_vault_key) MÁS los secretos-cliente (enc_key, vault_key) para que los
    tests puedan comprobar el round-trip sin volver a derivar."""
    salt = os.urandom(16)
    mk = derive_master_key(master_password, salt, params)
    auth_key = derive_auth_key(mk)
    enc_key = derive_enc_key(mk)
    vault_key = os.urandom(32)
    wrapped_vault_key = wrap_key(enc_key, vault_key)
    return {
        "kdf_salt": base64.b64encode(salt).decode(),
        "kdf_params": dict(params),
        "auth_key_b64": base64.b64encode(auth_key).decode(),
        "wrapped_vault_key": wrapped_vault_key,
        "enc_key": enc_key,
        "vault_key": vault_key,
    }


# =========================================================================== #
# Credenciales de fixture — tres restricciones simultáneas (§6)
# =========================================================================== #
# - sin `;` / `--` / `DELETE`  (detect_suspicious_request; prudencia y cruce con G6)
# - >= 12 caracteres           (MinimumLengthValidator a 12)
# - pasan CustomPasswordValidator (mayús+minús+número+símbolo, sin secuencias/fechas/
#   palabras prohibidas)
TEST_ACCOUNT_PASSWORD = "Wren$Kilo7pluto"   # contraseña de la cuenta Django
TEST_MASTER_PASSWORD = "Vault$Otter9lynx"   # contraseña maestra ZK (deriva la MK)


class ZKUser:
    """Contenedor de un usuario de test con material ZK ya sembrado."""

    def __init__(self, user, crypto, material, credentials):
        self.user = user
        self.crypto = crypto          # instancia UserCrypto
        self.material = material       # dict de build_user_crypto_material
        self.credentials = credentials


# =========================================================================== #
# Chequeos previos y aislamiento
# =========================================================================== #
@pytest.fixture(scope="session", autouse=True)
def _require_redis_reachable():
    """Aborta pronto y claro si Redis no responde (§6, chequeos previos).

    Con IGNORE_EXCEPTIONS=False (M6), un Redis caído hace fallar en cascada tests que
    nada tienen que ver con la caché. Mejor un mensaje que 40 errores crípticos."""
    from django.core.cache import caches

    try:
        caches["default"].set("__pytest_ping__", "1", timeout=5)
        assert caches["default"].get("__pytest_ping__") == "1"
        caches["default"].delete("__pytest_ping__")
    except Exception as exc:  # noqa: BLE001
        pytest.exit(
            "Redis inalcanzable desde la caché 'default'. L1 exige la pila levantada "
            f"(docker compose up). Motivo: {exc!r}",
            returncode=3,
        )
    yield


@pytest.fixture(autouse=True)
def _clear_caches_around_each_test():
    """Limpia `default` y `sessions` ANTES y DESPUÉS de cada test (trampa 10).

    Los middleware escriben en Redis en cada petición; sin esto el estado se filtra
    entre casos. En db 15 con KEY_PREFIX='test' (settings_test), así que jamás toca
    los contadores/sesiones reales de la app (db 1 y db 2)."""
    from django.core.cache import caches

    def _clear():
        for name in ("default", "sessions"):
            try:
                caches[name].clear()
            except Exception:  # noqa: BLE001
                # El precheck de sesión ya habría abortado si Redis no va; aquí no
                # convertimos un fallo de limpieza en un error de test ajeno.
                pass

    _clear()
    yield
    _clear()


# =========================================================================== #
# Fixtures de usuario ZK (sembrado por ORM)
# =========================================================================== #
@pytest.fixture
def zk_credentials() -> dict:
    """Credenciales que cumplen las tres restricciones del §6."""
    return {
        "username": "zk_tester_alpha",
        "email": "zk_tester_alpha@example.test",
        "password": TEST_ACCOUNT_PASSWORD,
        "master_password": TEST_MASTER_PASSWORD,
    }


@pytest.fixture
def zk_user(db, django_user_model, zk_credentials) -> ZKUser:
    """Usuario de test con UserCrypto sembrado por ORM (material ZK real, trampa 7).

    Reproduce lo que haría el cliente en el registro: deriva AuthKey/EncKey de la
    maestra, genera una VaultKey aleatoria y la envuelve con la EncKey. El servidor
    sólo guarda `auth_key_hash = make_password(AuthKey)` y `wrapped_vault_key`."""
    from myapp.models import UserCrypto

    user = django_user_model.objects.create_user(
        username=zk_credentials["username"],
        email=zk_credentials["email"],
        password=zk_credentials["password"],
    )
    material = build_user_crypto_material(zk_credentials["master_password"])
    crypto = UserCrypto(
        user=user,
        kdf_salt=material["kdf_salt"],
        kdf_params=material["kdf_params"],
        wrapped_vault_key=material["wrapped_vault_key"],
        crypto_version=UserCrypto.CURRENT_CRYPTO_VERSION,
    )
    crypto.set_auth_key(material["auth_key_b64"])  # guarda Argon2id(AuthKey)
    crypto.save()
    return ZKUser(user=user, crypto=crypto, material=material, credentials=zk_credentials)
