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

Alcance: una sesión de login (N9)
---------------------------------
El marcador es por **sesión de login** (claim `sid`, ver `login_session`), no por usuario. Por
usuario, desbloquear la bóveda en un navegador la desbloqueaba en todos: otro navegador que sólo
conocía la maestra podía añadir y leer entradas sin haber probado la contraseña del vault. Las
invalidaciones (cambio de contraseña, conversión, borrado) sí afectan a todas las sesiones.

Política de caché (M6)
----------------------
El marcador es un **control de autorización**: si Redis no responde no se puede afirmar que la
bóveda esté desbloqueada, así que se falla cerrado (deniega). Por eso la comprobación es
`strict_*` y traduce `CacheUnavailable` a 503, igual que el guardián de la maestra. El borrado
(al bloquear o cambiar la contraseña del vault) es `lenient`: no poder borrarlo sólo puede
volver el control más estricto, nunca más laxo.
"""

from .cache_utils import (
    CacheUnavailable,
    lenient_delete_pattern,
    strict_get,
    strict_set,
)
from .login_session import session_id_from_request

# Vida del desbloqueo sin renovar. Se alinea con el auto-bloqueo por inactividad del cliente
# (cryptoSession, 15 min): la VaultKey en memoria y el marcador caducan a la vez.
VAULT_UNLOCK_TTL_SECONDS = 15 * 60


def _key(user_id, vault_id, session_id):
    return f"vault_unlocked_{user_id}_{vault_id}_{session_id}"


def mark_vault_unlocked(request, vault_id):
    """Registra la bóveda como desbloqueada para la sesión de esta petición, con TTL. Puede
    lanzar `CacheUnavailable` (fail-closed): si no se pudo escribir, la comprobación posterior
    denegará y el cliente reintenta. Sin sesión JWT no hay a qué atarlo y no se marca nada."""
    session_id = session_id_from_request(request)
    if session_id is None:
        return
    strict_set(_key(request.user.id, vault_id, session_id), 1, VAULT_UNLOCK_TTL_SECONDS)


def is_vault_unlocked(request, vault_id):
    """True si la sesión de esta petición tiene un marcador vigente. Lanza `CacheUnavailable` si la caché no responde (quien llama debe denegar con 503)."""
    session_id = session_id_from_request(request)
    if session_id is None:
        return False
    return bool(strict_get(_key(request.user.id, vault_id, session_id)))


def clear_vault_unlock(user_id, vault_id):
    """Olvida el desbloqueo en TODAS las sesiones del usuario (al rotar la contraseña del vault,
    convertir su privacidad o borrarlo). Lenient."""
    lenient_delete_pattern(f"vault_unlocked_{user_id}_{vault_id}_*")


def guard_private_vault_access(request, vault):
    """Gate reutilizable para las vistas: si la bóveda es privada v2, exige marcador de
    desbloqueo de la sesión de la petición. Devuelve `None` si el acceso puede seguir, o un
    `JsonResponse` (403/503) que quien llama debe devolver tal cual.

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
