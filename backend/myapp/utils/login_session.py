"""Identificador de la sesión de login dentro del JWT (claim `sid`, N9).

El problema que resuelve
------------------------
Un JWT dice *quién* es el usuario, pero no *desde qué login* habla. El access cambia de `jti`
cada vez que se renueva y el refresh rota con `ROTATE_REFRESH_TOKENS`, así que ninguno de los
dos sirve para reconocer «el mismo navegador» a lo largo de la sesión. Sin ese dato, el
marcador de desbloqueo de bóvedas privadas (`vault_unlock`) quedaba atado sólo al usuario: un
segundo navegador que sólo conocía la maestra heredaba el desbloqueo de otro.

Cómo vive el claim
------------------
Se pone una vez, en el **refresh** que se emite al hacer login o registrarse. simplejwt copia
al access todos los claims del refresh salvo `token_type`, `exp`, `jti` e `iat`
(`RefreshToken.no_copy_claims`), y al rotar reutiliza el mismo payload cambiando sólo esos
cuatro (`TokenRefreshSerializer.validate`). Así `sid` dura exactamente lo que dura el login:
nace con él, sobrevive a cada renovación y muere con el refresh.

Transición
----------
Los tokens emitidos antes de este cambio no llevan `sid`. Para ellos se usa el `jti` del
access: aísla incluso más (cada renovación es una «sesión» nueva), a costa de tener que
desbloquear otra vez la bóveda tras cada refresh. El caso desaparece solo cuando caducan los
refresh antiguos (`REFRESH_TOKEN_LIFETIME`, 7 días).
"""

import uuid

SESSION_ID_CLAIM = 'sid'


def stamp_session_id(refresh):
    """Asigna un `sid` nuevo al refresh recién emitido. Llamar ANTES de derivar el access
    (`refresh.access_token`), que es cuando simplejwt copia los claims."""
    refresh[SESSION_ID_CLAIM] = uuid.uuid4().hex
    return refresh


def session_id_from_request(request):
    """`sid` del token con el que se autenticó la petición, o el `jti` del access si el token
    es anterior al claim. `None` si la petición no trae un JWT validado (quien llama debe tratar
    la bóveda como bloqueada)."""
    token = getattr(request, 'auth', None)
    if token is None or not hasattr(token, 'get'):
        return None
    return token.get(SESSION_ID_CLAIM) or token.get('jti')
