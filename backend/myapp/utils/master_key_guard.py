"""Bloqueo exponencial por usuario ante fallos de contraseña maestra (A3).

El problema que resuelve
-----------------------
`RateLimitMiddleware` sólo trataba como sensible `/api/master-key/verify/`. Las
demás rutas que **también** validan la contraseña maestra caían en `data` o
`normal`, es decir sin límite alguno: `/api/unlock-password/<id>/`,
`/api/unlock-all-accounts/`, `/api/batch-delete-passwords/`, las tres de
`/passwords/…` y las de descarga y borrado de ficheros. Cualquiera de ellas era
un oráculo de fuerza bruta ilimitada contra la maestra, y bastaba con cambiar de
ruta para esquivar el único límite que existía.

La reclasificación en `classify_endpoint` cierra esa vía, pero no basta por sí
sola: el contador `sensitive` es por identificador y **cuenta operaciones, no
fallos**, así que un atacante con 50 intentos por hora seguiría avanzando, y un
usuario legítimo que trabaja mucho consumiría el mismo presupuesto que quien
ataca. Este módulo añade el control que faltaba: un contador que sólo mira
**fallos consecutivos de la maestra**, por usuario, con espera exponencial.

La curva
--------
Los cuatro primeros fallos no cuestan nada: escribir mal una contraseña larga es
normal. A partir del quinto la espera se dobla —30 s, 60 s, 120 s…— hasta un
tope de una hora. Veinte intentos seguidos cuestan del orden de diez horas de
espera acumulada, lo que hace inviable recorrer un diccionario, mientras que
equivocarse dos o tres veces sigue sin penalización perceptible.

El contador es de fallos **consecutivos** y se borra al acertar, así que un
usuario legítimo nunca arrastra deuda de sesiones anteriores.

Política de caché (M6)
----------------------
Los contadores son `strict_*`: si Redis no responde no se puede afirmar que
quien llama esté dentro de su límite, y dejar pasar sería reabrir exactamente el
agujero que este módulo cierra. La única excepción es el borrado del contador
tras un acierto, que es `lenient_delete`: no poder borrarlo sólo puede volver el
control **más** estricto, nunca más laxo, y negar una operación ya autorizada
porque Redis parpadeó sería peor que arrastrar un contador de más.

`CacheUnavailable` se captura **aquí dentro** y se traduce a 503. Así la
denegación no puede acabar tragada por el `except Exception` genérico que
tienen casi todas las vistas, que la convertiría en un 500 opaco y fuera de los
logs de seguridad.
"""

import logging
import time

from django.http import JsonResponse

from .cache_utils import (
    CacheUnavailable,
    lenient_delete,
    service_unavailable_response,
    strict_get,
    strict_set,
)

security_logger = logging.getLogger('security')

# Fallos que no cuestan nada. El primero penalizado es el siguiente.
FREE_ATTEMPTS = 4
# Espera del primer fallo penalizado; se dobla en cada uno posterior.
BASE_DELAY_SECONDS = 30
MAX_DELAY_SECONDS = 3600
# Cuánto vive el contador sin nuevos fallos. Es de fallos consecutivos: un
# acierto lo borra antes de que llegue a caducar.
FAILURE_WINDOW_SECONDS = 86400


def _failure_key(user_id):
    return f"master_key_failures_{user_id}"


def _lock_key(user_id):
    return f"master_key_lock_until_{user_id}"


def _lock_remaining(user_id):
    """Segundos que quedan de bloqueo, o 0 si no lo hay.

    Se guarda el instante de fin y no sólo el TTL para poder devolver un
    `retry_after` exacto al cliente.
    """
    locked_until = strict_get(_lock_key(user_id))
    if not locked_until:
        return 0
    remaining = int(locked_until - time.time())
    return remaining if remaining > 0 else 0


def _register_failure(user_id):
    """Suma un fallo y devuelve los segundos de bloqueo que impone (0 si ninguno)."""
    failures = (strict_get(_failure_key(user_id)) or 0) + 1
    strict_set(_failure_key(user_id), failures, FAILURE_WINDOW_SECONDS)

    if failures <= FREE_ATTEMPTS:
        return 0

    delay = min(
        BASE_DELAY_SECONDS * (2 ** (failures - FREE_ATTEMPTS - 1)),
        MAX_DELAY_SECONDS,
    )
    strict_set(_lock_key(user_id), time.time() + delay, delay)
    return delay


def _locked_response(retry_after):
    """429 sin decir cuántos intentos van ni cuántos quedan.

    El texto evita la palabra "incorrecta" a propósito: el frontend clasifica
    los errores por subcadena y esto no es un fallo de credencial, es un límite.
    """
    response = JsonResponse({
        'success': False,
        'error': 'Demasiados intentos fallidos con la contraseña maestra. '
                 'Vuelve a intentarlo más tarde.',
        'code': 'MASTER_KEY_LOCKED',
        'retry_after': retry_after,
    }, status=429)
    response['Retry-After'] = str(retry_after)
    return response


def _invalid_response():
    """400, el mismo estado que devolvían las vistas antes de unificarlas."""
    return JsonResponse({
        'success': False,
        'error': 'Contraseña maestra incorrecta',
    }, status=400)


def _guard(user, verify_fn):
    """Núcleo del bloqueo exponencial, independiente de CÓMO se verifica el secreto.

    Devuelve `None` si `verify_fn()` da True (la operación puede seguir), o un
    `JsonResponse` que quien llama debe devolver tal cual:

    - **429** si el usuario está bloqueado, o si este fallo es el que activa el
      bloqueo. Devolver 429 ya en el fallo que lo dispara (y no en el
      siguiente) es lo que hace que un script de fuerza bruta se encuentre el
      límite en el intento que lo cruza.
    - **400** si el secreto es incorrecto y aún no toca bloquear.
    - **503** si la caché no responde: sin contador no hay límite, y este
      control es lo único que separa la clave maestra de la fuerza bruta.
    """
    user_id = user.id

    try:
        remaining = _lock_remaining(user_id)
        if remaining > 0:
            security_logger.warning(
                "Clave maestra bloqueada para el usuario %s: quedan %s s",
                user_id, remaining,
            )
            return _locked_response(remaining)

        if verify_fn():
            # Fallos consecutivos: acertar borra la cuenta. Lenient a
            # propósito (ver la nota de política de caché en el docstring).
            lenient_delete(_failure_key(user_id))
            return None

        delay = _register_failure(user_id)
        security_logger.warning(
            "Fallo de clave maestra del usuario %s%s",
            user_id,
            f"; bloqueado {delay} s" if delay else "",
        )
        return _locked_response(delay) if delay else _invalid_response()

    except CacheUnavailable:
        security_logger.error(
            "Bloqueo de clave maestra no disponible (caché caída): "
            "denegando la verificación del usuario %s", user_id,
        )
        return service_unavailable_response()


def guard_master_password(user, master_key_entry, raw_key):
    """Guard del esquema legado (MasterKey.verify_master_key). Se conserva hasta la purga
    de datos del paso 26. Sustituyó al patrón `if not verify_master_key(x): return 400`
    repetido en catorce vistas."""
    return _guard(user, lambda: master_key_entry.verify_master_key(raw_key))


def guard_auth_key(user, user_crypto, auth_key_b64):
    """Guard del esquema zero-knowledge (Fase 2). Verifica la AuthKey derivada en el cliente
    contra `UserCrypto.verify_auth_key`, con el mismo bloqueo exponencial por usuario.

    Es el sustituto de `guard_master_password` cuando la verificación ya no puede pasar por
    descifrar nada en el servidor: aquí sólo se comprueba Argon2id(AuthKey), nunca la maestra.
    """
    return _guard(user, lambda: user_crypto.verify_auth_key(auth_key_b64))
