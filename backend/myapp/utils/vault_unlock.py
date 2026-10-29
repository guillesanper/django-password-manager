"""Marcador de desbloqueo de bóveda privada en servidor (paso 24, A9).

El problema que resuelve
------------------------
Antes, el cliente enviaba `vault_already_unlocked=True` y el servidor se lo creía: un booleano
de confianza que cualquiera con una sesión podía poner a mano. Este módulo lo sustituye por un
marcador que **pone el servidor** tras verificar posesión de la subclave (`guard_vault_auth_key`)
y que **comprueba el servidor** antes de servir o aceptar contenido de una bóveda privada.

La protección real de una bóveda privada es criptográfica: su contenido va cifrado bajo la
`VaultSubKey`, que sólo se deriva con la contraseña del vault (§8). Este marcador es
defensa en profundidad: evita entregar siquiera el ciphertext/metadatos a una sesión que no ha
probado la contraseña del vault, y da un punto único para el gate.

Por sesión, no por usuario (N9)
-------------------------------
El marcador era `vault_unlocked_<user>_<vault>`, compartido por todas las sesiones del
usuario: si un navegador desbloqueaba la bóveda, otro que sólo conocía la maestra pasaba el
gate, metía entradas (que su cliente cifraba con la VaultKey principal) y las leía en claro.
Ahora la clave lleva además el identificador de la sesión de login (`login_session`): el
desbloqueo sólo vale para el navegador que probó la contraseña del vault.

Las revocaciones, en cambio, son de **todas** las sesiones: cambiar la contraseña de la
bóveda, hacerla pública o borrarla invalida cualquier desbloqueo previo, sea de quien sea.
No hay revocación de una sola sesión porque el servidor no tiene endpoint de «bloquear»: el
bloqueo local del cliente sólo olvida la subclave, y el marcador caduca por su TTL.

Política de caché (M6)
----------------------
El marcador es un **control de autorización**: si Redis no responde no se puede afirmar que la
bóveda esté desbloqueada, así que se falla cerrado (deniega). Por eso la comprobación es
`strict_*` y traduce `CacheUnavailable` a 503, igual que el guardián de la maestra.

La revocación también es `strict_*` (N9). Antes era `lenient` con el argumento de que no poder
borrar «sólo vuelve el control más estricto», pero es al revés: el marcador que no se borra
sigue autorizando hasta su TTL, y con la renovación por uso podría no caducar nunca.
Quien revoca lo hace ANTES de tocar la BD, y si no puede, responde 503 sin cambiar nada.

La renovación del TTL es `lenient`: no poder renovarlo sólo adelanta la caducidad.
"""

import logging

from .cache_utils import (
    CacheUnavailable,
    lenient_touch,
    strict_delete_pattern,
    strict_get,
    strict_set,
)
from .login_session import session_id_from_request

logger = logging.getLogger(__name__)

# Vida del desbloqueo sin uso. Se alinea con el auto-bloqueo por inactividad del cliente
# (cryptoSession, 15 min): los dos se renuevan con el uso (N9), así que caducan tras el mismo
# rato de inactividad y no a los 15 min de haber desbloqueado.
VAULT_UNLOCK_TTL_SECONDS = 15 * 60


def _prefix(user_id, vault_id):
    # El `_` final separa el id de la bóveda del de la sesión: el patrón de la bóveda 1 no
    # debe casar con las claves de la bóveda 12.
    return f"vault_unlocked_{user_id}_{vault_id}_"


def _key(request, vault_id):
    """Clave del marcador para la sesión de `request`, o `None` si no hay sesión identificable."""
    session_id = session_id_from_request(request)
    if not session_id:
        return None
    return _prefix(request.user.id, vault_id) + str(session_id)


def mark_vault_unlocked(request, vault_id):
    """Registra la bóveda como desbloqueada para la sesión de `request`, con TTL. Puede lanzar
    `CacheUnavailable` (fail-closed): si no se pudo escribir, la comprobación posterior denegará
    y el cliente reintenta."""
    key = _key(request, vault_id)
    if key is None:
        # Sin JWT no hay sesión a la que atar el desbloqueo: la bóveda sigue bloqueada.
        logger.warning("Desbloqueo de la bóveda %s sin sesión identificable", vault_id)
        return
    strict_set(key, 1, VAULT_UNLOCK_TTL_SECONDS)


def is_vault_unlocked(request, vault_id):
    """True si esta sesión tiene un marcador vigente, y en ese caso renueva su TTL (N9). Lanza
    `CacheUnavailable` si la caché no responde (quien llama debe denegar con 503).

    Antes el marcador caducaba a los 15 min de desbloquear aunque se estuviera usando la bóveda,
    mientras el cliente, que renueva con el uso, seguía considerándola abierta: `VAULT_LOCKED` en
    mitad del trabajo."""
    key = _key(request, vault_id)
    if key is None:
        return False
    if not strict_get(key):
        return False
    lenient_touch(key, VAULT_UNLOCK_TTL_SECONDS)
    return True


def revoke_vault_unlocks(user_id, vault_id):
    """Olvida el desbloqueo de la bóveda en TODAS las sesiones del usuario (al cambiar su
    contraseña, hacerla pública o borrarla). Strict: lanza `CacheUnavailable` si no se pudo, y
    quien llama debe responder 503 antes de modificar nada."""
    strict_delete_pattern(_prefix(user_id, vault_id) + "*")


def guard_private_vault_access(request, vault):
    """Gate reutilizable para las vistas: si la bóveda es privada v2, exige que ESTA sesión tenga
    marcador de desbloqueo. Devuelve `None` si el acceso puede seguir, o un `JsonResponse` (403/503) que
    quien llama debe devolver tal cual.

    Las bóvedas públicas y las privadas legadas (v1, sin subclave) no tienen gate aquí: las v1
    se retiran en el paso 26/27 y hasta entonces su contenido ya es opaco bajo la VaultKey.
    """
    from django.http import JsonResponse

    if not vault.is_private or vault.vault_crypto_version < 2:
        return None

    try:
        if is_vault_unlocked(request, vault.id):
            return None
    except CacheUnavailable:
        return _service_unavailable()

    return JsonResponse({
        'success': False,
        'error': 'La bóveda está bloqueada. Desbloquéala con su contraseña.',
        'code': 'VAULT_LOCKED',
    }, status=403)


def _service_unavailable():
    from .cache_utils import service_unavailable_response
    return service_unavailable_response()
