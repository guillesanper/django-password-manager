"""Helpers PUROS de L2 (sin fixtures), importables desde conftest.py y los tests.

Módulo con nombre propio (no `conftest`) para poder hacer `from _l2lib import ...`
sin chocar con el conftest de la raíz. La detección de pila, el hook de skip y las
fixtures viven en conftest.py; aquí sólo funciones y constantes reutilizables.
"""

import json
import socket
import subprocess
import time

import pytest

# --------------------------------------------------------------------------- #
# URLs base y puertos.
# --------------------------------------------------------------------------- #
_DEV_PORT = 8000
_PROD_PORT = 443

BASE_URL_DEV = "http://localhost:8000"
BASE_URL_PROD = "https://localhost"        # nginx, TLS autofirmado
BASE_URL_PROD_HTTP = "http://localhost"    # :80, sólo redirige (A12-b)


def port_open(port, host="127.0.0.1", timeout=1.5):
    """True si hay algo escuchando en host:port (TCP connect)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def esperar_pila_lista(base_url, timeout=150, intervalo=2):
    """Espera a que la aplicación CONTESTE, no sólo a que el puerto esté abierto.

    El puerto abierto no significa aplicación en pie: Docker publica el puerto en
    cuanto arranca el contenedor, mientras dentro siguen corriendo `migrate` y
    `setup_minio_buckets` y `runserver`/gunicorn todavía no escuchan. En esa
    ventana el proxy acepta la conexión y la cierra sin responder, que en el
    cliente se ve como `ConnectionError: RemoteDisconnected` — y como la detección
    de pila es un `connect()` TCP, los tests se ejecutan igualmente y fallan en
    bloque por una razón ajena a lo que prueban.

    Se sondea `/health/` (AllowAny, sin efectos) hasta obtener una respuesta HTTP
    real. Devuelve esa respuesta; si nunca llega, SALTA con el motivo (no es un
    fallo del código bajo prueba, es la pila que no está lista).
    """
    import requests  # local: conftest ya ha silenciado el aviso de TLS autofirmado

    fin = time.time() + timeout
    ultimo = None
    while time.time() < fin:
        try:
            return requests.get(base_url + "/health/", timeout=5, verify=False)
        except requests.RequestException as exc:
            ultimo = exc
            time.sleep(intervalo)

    pytest.skip(
        f"La pila publica el puerto pero no responde en {base_url}/health/ tras "
        f"{timeout} s ({type(ultimo).__name__}). Revisa `docker compose logs -f web`: "
        "probablemente sigue con migrate/setup_minio_buckets, o el arranque falló."
    )


# --------------------------------------------------------------------------- #
# docker compose (el ORM vive en el contenedor, §2.1).
# --------------------------------------------------------------------------- #
def compose_run(compose_prefix, backend_dir, args, timeout=180, extra_env=None):
    """Ejecuta `docker compose ... <args>` en backend/. Salta si no hay docker."""
    cmd = list(compose_prefix) + list(args)
    try:
        return subprocess.run(
            cmd,
            cwd=str(backend_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=extra_env,
        )
    except FileNotFoundError:
        pytest.skip("`docker` no está en el PATH del host; L2 de despliegue lo necesita.")


def container_web_logs(compose_prefix, backend_dir, timeout=120):
    """Logs completos del servicio `web` (sin color), para C4-b / A11-b."""
    res = compose_run(
        compose_prefix, backend_dir, ["logs", "--no-color", "web"], timeout=timeout
    )
    return (res.stdout or "") + "\n" + (res.stderr or "")


def container_exec_python(compose_prefix, backend_dir, code, seed_env=None, timeout=180):
    """Corre `manage.py shell -c <code>` en `web`, pasando variables con -e.

    El ORM se ejecuta con la settings de PRODUCCIÓN del contenedor (demo.settings):
    la misma BD/bucket que sirve la app a la que ataca el cliente HTTP. NO usa
    settings_test (eso es de L1).
    """
    args = ["exec", "-T"]
    for key, value in (seed_env or {}).items():
        args += ["-e", f"{key}={value}"]
    args += ["web", "python", "manage.py", "shell", "-c", code]
    return compose_run(compose_prefix, backend_dir, args, timeout=timeout)


def flush_redis_rate_limits(compose_prefix, backend_dir):
    """Vacía db 1 y 2 de Redis (rate limit + sesiones) EN LA PILA REAL.

    ⚠️ Sólo para los tests SERIAL de rate limiting, que agotan a propósito el
    presupuesto de auth por IP; sin flush antes y después, los logins de los demás
    tests darían 429 en cascada (§6). Lee REDIS_PASSWORD del entorno del contenedor
    `redis` (no se imprime). No es autouse: la tanda serial lo invoca explícitamente.
    """
    script = (
        'redis-cli -a "$REDIS_PASSWORD" -n 1 FLUSHDB; '
        'redis-cli -a "$REDIS_PASSWORD" -n 2 FLUSHDB'
    )
    return compose_run(
        compose_prefix, backend_dir, ["exec", "-T", "redis", "sh", "-c", script], timeout=60
    )


# --------------------------------------------------------------------------- #
# CSRF de doble envío para peticiones mutantes autenticadas.
# --------------------------------------------------------------------------- #
def csrf_headers(session, base_url, extra=None):
    """Cabeceras para una petición mutante autenticada por cookie.

    - X-CSRFToken con el valor ACTUAL de la cookie `csrftoken` (doble envío;
      `login` rota el token, así que se relee en cada llamada).
    - Origin/Referer del propio origen: sobre HTTPS, el CsrfViewMiddleware exige
      además la comprobación de Origin/Referer, y un same-origin siempre se acepta.
      Sin esto, el POST por el 443 daría 403 "Referer checking failed".
    """
    token = session.cookies.get("csrftoken")
    headers = {
        "X-CSRFToken": token or "",
        "Origin": base_url,
        "Referer": base_url + "/",
    }
    if extra:
        headers.update(extra)
    return headers


# --------------------------------------------------------------------------- #
# Derivación zero-knowledge EN EL CONTENEDOR (§7.1, trampas 7 y 14).
# --------------------------------------------------------------------------- #
# El HOST sólo tiene pytest/requests: NO tiene argon2-cffi ni cryptography, así que
# no puede derivar una AuthKey/SubAuthKey válida. Toda la cripto vive en el
# contenedor `web` (que ya tiene ambas) y el host se limita a transportar base64.
#
# Espejo exacto de crypto.ts (y del helper del conftest de L1):
#   MK          = Argon2id(password, salt, m=65536 KiB, t=3, p=4, len=32, v=19)
#   AuthKey     = HKDF-SHA256(MK, salt="", info="auth")   -> el servidor guarda su Argon2id
#   EncKey      = HKDF-SHA256(MK, salt="", info="enc")    -> nunca sale del cliente
#   wrapped_*   = base64( nonce(12) || AES-256-GCM(EncKey, clave) )        SIN AAD
#   ciphertext  = base64( nonce(12) || AES-256-GCM(VaultKey, json) )  AAD = user|client_id|ver
#
# Los fragmentos van en ASCII puro a propósito: viajan como argumento de
# `manage.py shell -c` y su salida se decodifica con la codificación del host.
_ZK_PRELUDE = r"""
import os, base64, json, uuid
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.contrib.auth.models import User
from myapp.models import UserCrypto, Vault, PasswordEntry

KDF_PARAMS = {'algo': 'argon2id', 'm': 65536, 't': 3, 'p': 4, 'hashLen': 32, 'version': 19}

def derive(password, salt):
    mk = hash_secret_raw(
        secret=password.encode('utf-8'), salt=salt,
        time_cost=3, memory_cost=65536, parallelism=4, hash_len=32,
        type=Type.ID, version=19,
    )
    def _hkdf(info):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b'', info=info).derive(mk)
    return _hkdf(b'auth'), _hkdf(b'enc')

def wrap(enc_key, raw_key):
    nonce = os.urandom(12)
    return base64.b64encode(nonce + AESGCM(enc_key).encrypt(nonce, raw_key, None)).decode()

def unwrap(enc_key, wrapped_b64):
    blob = base64.b64decode(wrapped_b64)
    return AESGCM(enc_key).decrypt(blob[:12], blob[12:], None)

def seal(key_raw, plaintext, aad):
    nonce = os.urandom(12)
    ct = AESGCM(key_raw).encrypt(nonce, plaintext.encode('utf-8'), aad.encode('utf-8'))
    return base64.b64encode(nonce + ct).decode()

def open_(key_raw, ciphertext_b64, aad):
    blob = base64.b64decode(ciphertext_b64)
    return AESGCM(key_raw).decrypt(blob[:12], blob[12:], aad.encode('utf-8')).decode('utf-8')

def emit(marker, payload):
    print(marker + ' ' + json.dumps(payload))
"""

# Sembrado (trampa 7: la BD arranca vacía). Deja listo TODO lo que los tests de
# stack_dev necesitan mandar por HTTP:
#   - usuario + UserCrypto (material principal)
#   - una entrada SIN bóveda, cifrada bajo la VaultKey        -> A7, Z10/M8
#   - una bóveda privada v2 + su entrada, bajo la VaultSubKey -> Z11/A9
# La bóveda privada queda BLOQUEADA: sembrar por ORM no pone el marcador de
# desbloqueo (eso sólo lo pone el servidor tras probar la subclave), que es
# justo el estado de partida que Z11 necesita.
SEED_CODE = _ZK_PRELUDE + r"""
email = os.environ['SEED_EMAIL']
username = os.environ['SEED_USERNAME']

# Idempotente: barre restos de una corrida anterior que muriera sin teardown.
User.objects.filter(email=email).delete()
User.objects.filter(username=username).delete()

u = User.objects.create_user(
    username=username, email=email, password=os.environ['SEED_DJANGO_PWD'],
)

# --- material principal (espejo de setupUserCrypto) ---
salt = os.urandom(16)
auth_key, enc_key = derive(os.environ['SEED_MASTER_PWD'], salt)
vault_key = os.urandom(32)

c = UserCrypto(
    user=u,
    kdf_salt=base64.b64encode(salt).decode(),
    kdf_params=KDF_PARAMS,
    wrapped_vault_key=wrap(enc_key, vault_key),
    crypto_version=UserCrypto.CURRENT_CRYPTO_VERSION,
)
c.set_auth_key(base64.b64encode(auth_key).decode())
c.save()

# --- entrada sin boveda, cifrada bajo la VaultKey principal ---
entry_plain = json.dumps(
    {'website': 'ejemplo-l2.test', 'username': 'l2-cuenta', 'password': 'Blob$Opaco9zk'},
    separators=(',', ':'),
)
entry_cid = str(uuid.uuid4())
entry = PasswordEntry.objects.create(
    user=u, vault=None, client_id=entry_cid, crypto_version=2,
    ciphertext=seal(vault_key, entry_plain, '%s|%s|2' % (u.id, entry_cid)),
)

# --- boveda privada v2 (espejo de setupVaultSubKey) + entrada dentro ---
sub_salt = os.urandom(16)
sub_auth_key, sub_enc_key = derive(os.environ['SEED_VAULT_PWD'], sub_salt)
sub_key = os.urandom(32)

v = Vault.objects.create(
    user=u, name='L2 privada', description='boveda privada de test L2',
    color='blue', is_private=True,
)
v.sub_kdf_salt = base64.b64encode(sub_salt).decode()
v.sub_kdf_params = KDF_PARAMS
v.wrapped_vault_subkey = wrap(sub_enc_key, sub_key)
v.vault_crypto_version = 2
v.set_sub_auth_key(base64.b64encode(sub_auth_key).decode())
v.save()

vault_plain = json.dumps(
    {'website': 'privada-l2.test', 'username': 'l2-privada', 'password': 'Sub$Clave7zk'},
    separators=(',', ':'),
)
vault_cid = str(uuid.uuid4())
vault_entry = PasswordEntry.objects.create(
    user=u, vault=v, client_id=vault_cid, crypto_version=2,
    ciphertext=seal(sub_key, vault_plain, '%s|%s|2' % (u.id, vault_cid)),
)

print('SEED_OK', u.id)
emit('SEED_JSON', {
    'user_id': u.id,
    'kdf_salt': c.kdf_salt,
    'kdf_params': KDF_PARAMS,
    'wrapped_vault_key': c.wrapped_vault_key,
    'auth_key': base64.b64encode(auth_key).decode(),
    'entry_id': entry.id,
    'entry_client_id': entry_cid,
    'entry_plaintext': entry_plain,
    'entry_website': 'ejemplo-l2.test',
    'vault_id': v.id,
    'vault_sub_auth_key': base64.b64encode(sub_auth_key).decode(),
    'vault_entry_id': vault_entry.id,
    'vault_entry_client_id': vault_cid,
    'vault_entry_plaintext': vault_plain,
    'vault_entry_website': 'privada-l2.test',
})
"""

# Rotación de la maestra (Z10/M8): espejo EXACTO de `rotateMasterPassword`.
# Lee el material vigente de la BD, desenvuelve la VaultKey con la EncKey ACTUAL y
# la re-envuelve con la EncKey NUEVA — la VaultKey no cambia, luego los ciphertext
# de las entradas no se tocan. Devuelve el cuerpo que espera /api/master-key/change/.
ROTATE_CODE = _ZK_PRELUDE + r"""
uc = UserCrypto.objects.get(user__email=os.environ['SEED_EMAIL'])
cur_auth, cur_enc = derive(os.environ['CUR_MASTER_PWD'], base64.b64decode(uc.kdf_salt))
vault_key = unwrap(cur_enc, uc.wrapped_vault_key)   # lanza si la maestra actual no es la buena

new_salt = os.urandom(16)
new_auth, new_enc = derive(os.environ['NEW_MASTER_PWD'], new_salt)

emit('ROTATE_JSON', {
    'current_auth_key': base64.b64encode(cur_auth).decode(),
    'kdf_salt': base64.b64encode(new_salt).decode(),
    'kdf_params': KDF_PARAMS,
    'auth_key': base64.b64encode(new_auth).decode(),
    'wrapped_vault_key': wrap(new_enc, vault_key),
})
"""

# Desbloqueo de verdad (Z10/M8): con SÓLO la contraseña maestra y el material que
# el SERVIDOR acaba de devolver por HTTP, deriva la EncKey, desenvuelve la VaultKey
# y descifra el ciphertext que el servidor devolvió por HTTP. Nada sale de la BD:
# todo entra por variables de entorno desde el host. El texto claro se emite en
# base64 para no depender de la codificación del host.
DECRYPT_CODE = _ZK_PRELUDE + r"""
_auth, enc = derive(os.environ['MASTER_PWD'], base64.b64decode(os.environ['KDF_SALT']))
vault_key = unwrap(enc, os.environ['WRAPPED_VAULT_KEY'])
plano = open_(vault_key, os.environ['CIPHERTEXT'], os.environ['ENTRY_AAD'])
emit('DECRYPT_JSON', {'plaintext_b64': base64.b64encode(plano.encode('utf-8')).decode()})
"""

# Sonda de estado de una cuenta recién registrada por HTTP (M9, Fase 3).
PROBE_USER_CODE = r"""
import os, json
from django.contrib.auth.models import User
u = User.objects.filter(email=os.environ['SEED_EMAIL']).first()
print('PROBE_JSON ' + json.dumps({
    'exists': u is not None,
    'is_active': bool(u.is_active) if u else None,
}))
"""

CLEANUP_CODE = r"""
import os
from django.contrib.auth.models import User
from myapp.minio_service import enhanced_minio_service

email = os.environ['SEED_EMAIL']
for u in User.objects.filter(email=email):
    try:
        enhanced_minio_service.delete_user_files(u.id)
    except Exception as exc:
        print('minio cleanup warn:', exc)
    u.delete()
print('CLEANUP_OK')
"""

# --------------------------------------------------------------------------- #
# Lectura de la salida marcada del contenedor.
# --------------------------------------------------------------------------- #
def marked_json(res, marker):
    """Devuelve el dict de la línea `<MARKER> {json}` de la salida, o None.

    Se busca por marcador y no por "la última línea" porque `manage.py shell`
    puede escribir avisos por delante (y runserver, en dev, mezcla su log).
    """
    for stream in ((res.stdout or ""), (res.stderr or "")):
        for line in stream.splitlines():
            line = line.strip()
            if line.startswith(marker + " "):
                try:
                    return json.loads(line[len(marker) + 1:])
                except ValueError:
                    return None
    return None


def container_output(res):
    """stdout+stderr recortado, para mensajes de error legibles."""
    return ((res.stdout or "") + "\n" + (res.stderr or "")).strip()[:2000]


# --------------------------------------------------------------------------- #
# Credenciales de test.
# --------------------------------------------------------------------------- #
# §6: sin `;`/`--`/`DELETE`, >=12 chars, pasan CustomPasswordValidator
# (mayús+minús+número+símbolo, sin secuencias ni años de 4 dígitos ni las palabras
# prohibidas 'pass'/'master'/'user'/...). Email con prefijo reconocible para que el
# teardown (y una limpieza manual) sepa qué borrar.
L2_USERNAME = "l2zktester"
L2_EMAIL = "l2_zk_tester@example.test"
L2_DJANGO_PASSWORD = "Wren$Kilo7pluto"
L2_MASTER_PASSWORD = "Vault$Otter9lynx"
# Contraseña de la bóveda privada: SEGUNDO secreto, independiente de la maestra
# (§8 / paso 24). Nunca llega al servidor: sólo su SubAuthKey derivada.
L2_VAULT_PASSWORD = "Lynx$Nimbus4otter"
# Maestra destino de la rotación de Z10/M8. El test rota y vuelve a rotar a la
# original, para que el material del fixture quede como estaba.
L2_MASTER_PASSWORD_NUEVA = "Nimbus$Wren5pluto"

# Usuario efímero del sondeo de M9 (registro por HTTP). Se borra al terminar.
L2_M9_EMAIL = "l2_m9_probe@example.test"
L2_M9_PASSWORD = "Kilo$Wren7probe"
L2_M9_FIRST_NAME = "Prueba"
L2_M9_LAST_NAME = "Ele Dos"


class L2User:
    """Usuario de test L2 ya sembrado en la BD de la pila.

    `material` trae el resultado de la derivación ZK hecha en el contenedor
    (base64 listo para mandar por HTTP): auth_key, kdf_salt, kdf_params,
    wrapped_vault_key, la entrada sembrada y la bóveda privada con su SubAuthKey.
    Ver SEED_CODE para el inventario exacto de claves.
    """

    def __init__(self, user_id, email, username, django_password, master_password,
                 vault_password=None, material=None):
        self.user_id = user_id
        self.email = email
        self.username = username
        self.django_password = django_password
        self.master_password = master_password
        self.vault_password = vault_password
        self.material = material or {}
