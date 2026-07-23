"""Acceso a la caché con una política de fallo EXPLÍCITA por cada uso (M6).

El problema que resuelve
------------------------
La caché tenía `IGNORE_EXCEPTIONS: True`. Con ese ajuste, django-redis devuelve
`None` cuando Redis no responde, así que un `cache.get` fallido es
indistinguible de "esa clave no existe". Aplicado a los controles de seguridad,
que es donde se usa aquí, el resultado es:

    attempts = cache.get(f"failed_login_attempts_{ip}", [])   # -> [] si Redis cae
    return len(attempts) >= 5                                 # -> False, adelante

Es decir: **con Redis caído desaparecían el rate limiting del login, el bloqueo
de cuenta y el bloqueo por IP, sin un solo error en los logs.** Un atacante que
consiga tirar Redis —o que espere a que se caiga— obtiene fuerza bruta
ilimitada contra el login y contra la clave maestra. Ese es el fallo *fail-open*
de M6: la seguridad se apagaba sola y en silencio.

La decisión que hay que tomar en cada uso
-----------------------------------------
Poner `IGNORE_EXCEPTIONS: False` sin más traslada el problema al otro extremo:
cualquier excepción de Redis se convierte en un 500 en mitad de la petición. Por
eso este módulo obliga a elegir, en cada punto de uso, entre dos políticas:

- `strict_*` — **controles de autorización**. Si la caché no responde no se
  puede afirmar que el cliente esté dentro de su límite, así que se levanta
  `CacheUnavailable` y quien llama debe **denegar** (503). Es el caso del rate
  limiting de autenticación, del bloqueo de cuenta y del límite de registro:
  vale más quedarse sin servicio un rato que quedarse sin cerradura.

- `lenient_*` — **controles de detección y telemetría**. Aquí fallar cerrado
  sería absurdo: si la caché cae, negar el acceso a todo el mundo porque no
  podemos *contar* sondeos convierte una avería de Redis en una caída total,
  provocable desde fuera. Se registra un ERROR y se sigue. Es el caso del
  contador de escaneo, del enfriado de `SecurityEvent` y del seguimiento de
  sesiones, que es monitorización: la autorización real la da el JWT.

La regla, en una línea: **fallar cerrado cuando la caché es la que autoriza;
fallar abierto y a gritos cuando sólo observa.**

Nota sobre los tiempos de espera: fallar cerrado sólo sirve si el fallo es
rápido. `SOCKET_CONNECT_TIMEOUT`/`SOCKET_TIMEOUT` están fijados en `CACHES`
(settings.py) precisamente por esto; sin ellos, un Redis inalcanzable pero
enrutable dejaría al worker esperando el timeout de TCP.
"""

import logging

from django.core.cache import cache
from django.http import JsonResponse

security_logger = logging.getLogger('security')


class CacheUnavailable(RuntimeError):
    """La caché no respondió y el control que la necesitaba no puede decidir."""


def strict_get(key, default=None):
    try:
        return cache.get(key, default)
    except Exception as e:
        security_logger.exception("Caché no disponible al leer %r (fail-closed)", key)
        raise CacheUnavailable(key) from e


def strict_set(key, value, timeout=None):
    try:
        cache.set(key, value, timeout)
    except Exception as e:
        security_logger.exception("Caché no disponible al escribir %r (fail-closed)", key)
        raise CacheUnavailable(key) from e


def lenient_get(key, default=None):
    try:
        return cache.get(key, default)
    except Exception:
        security_logger.exception("Caché no disponible al leer %r (se continúa)", key)
        return default


def lenient_set(key, value, timeout=None):
    """Devuelve True si se pudo escribir."""
    try:
        cache.set(key, value, timeout)
        return True
    except Exception:
        security_logger.exception("Caché no disponible al escribir %r (se continúa)", key)
        return False


def lenient_delete(key):
    """Devuelve True si se pudo borrar."""
    try:
        cache.delete(key)
        return True
    except Exception:
        security_logger.exception("Caché no disponible al borrar %r (se continúa)", key)
        return False


def service_unavailable_response():
    """Respuesta única para todo control que falla cerrado.

    No dice que el problema sea Redis: eso es información de infraestructura
    que no le corresponde al cliente (M1). El `Retry-After` es lo que permite
    al frontend distinguirla de un 429 y reintentar en vez de cerrar la sesión.
    """
    response = JsonResponse({
        'success': False,
        'error': 'Servicio temporalmente no disponible. Inténtalo de nuevo en unos minutos.',
        'code': 'SERVICE_UNAVAILABLE',
    }, status=503)
    response['Retry-After'] = '60'
    return response
