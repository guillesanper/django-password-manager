"""Mínimos de los parámetros KDF que el cliente manda al servidor (N13, AU-09).

El problema que resuelve
------------------------
El cliente deriva la maestra (y la contraseña de cada bóveda privada) con los `kdf_params`
que el servidor le devuelve, y las vistas de setup, rotación y bóvedas guardaban cualquier
dict. Unos parámetros baratos (`{"m": 8, "t": 1, "p": 1}`) hacen que la AuthKey o la
SubAuthKey que el cliente envía después se rompan offline en segundos.

La defensa que cuenta está en el cliente (`assertKdfParams` en `crypto.ts`): es la única que
resiste a un servidor o a una BD comprometidos. Esta comprobación es la otra mitad: el servidor
nunca **guarda** unos parámetros que un cliente sano rechazaría, ni aunque los mande un cliente
con un fallo o alguien con una sesión robada. Así no se deja a un usuario con una bóveda que su
propio navegador ya no quiere abrir.

Se exige el dict completo y con enteros: el cliente siempre envía `KDF_PARAMS` entero, así que
una clave ausente o de otro tipo no viene de ningún flujo legítimo.
"""

from django.http import JsonResponse

# Los valores de KDF_PARAMS en crypto.ts. `m` en KiB (65536 KiB = 64 MiB); version 19 = Argon2 v1.3.
KDF_ALGO = 'argon2id'
KDF_MIN_MEMORY_KIB = 65536
KDF_MIN_ITERATIONS = 3
KDF_MIN_PARALLELISM = 1
KDF_HASH_LEN = 32
KDF_VERSION = 19


def _is_int(value):
    # bool es subclase de int en Python: `True` no es un coste de memoria.
    return isinstance(value, int) and not isinstance(value, bool)


def kdf_params_error(params):
    """Motivo por el que `params` no vale como parámetros KDF, o None si cumple los mínimos."""
    if not isinstance(params, dict):
        return 'debe ser un objeto'
    if params.get('algo') != KDF_ALGO:
        return f'algo debe ser {KDF_ALGO}'
    for key, minimum in (('m', KDF_MIN_MEMORY_KIB), ('t', KDF_MIN_ITERATIONS),
                         ('p', KDF_MIN_PARALLELISM)):
        value = params.get(key)
        if not _is_int(value) or value < minimum:
            return f'{key} debe ser un entero mayor o igual que {minimum}'
    for key, expected in (('hashLen', KDF_HASH_LEN), ('version', KDF_VERSION)):
        value = params.get(key)
        if not _is_int(value) or value != expected:
            return f'{key} debe ser {expected}'
    return None


def invalid_kdf_params_response(field, params):
    """400 si `params` (recibido como `field`) no cumple los mínimos; None si los cumple."""
    error = kdf_params_error(params)
    if error is None:
        return None
    return JsonResponse({
        'success': False,
        'error': f'{field} no válido: {error}',
        'code': 'KDF_PARAMS_INVALID',
    }, status=400)
