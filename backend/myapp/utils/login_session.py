"""Identificador de la sesión de login, viajando dentro del JWT (N9).

Para qué
--------
Algunos controles tienen que ser **por sesión** y no por usuario: el desbloqueo de una bóveda
privada (`vault_unlock`) es el caso. Antes su marcador era `vault_unlocked_<user>_<vault>`, así
que desbloquearla en un navegador la dejaba desbloqueada en **todos**: otro navegador que sólo
conocía la maestra podía meter y leer entradas sin haber probado nunca la contraseña del vault.

Por qué un claim `sid` y no otra cosa
-------------------------------------
- El `jti` del refresh cambia en cada renovación (`ROTATE_REFRESH_TOKENS`).
- La sesión de Django y la cookie `session_id` de `SessionManager` no existen para un cliente
  sólo-Bearer, y son candidatas a desaparecer (las tres fuentes de sesión se solapan).
- Un claim propio en el **refresh** sí sirve: simplejwt lo copia a cada access que emite
  (`RefreshToken.access_token` copia todo salvo `token_type`, `exp`, `jti` e `iat`) y lo
  conserva al rotar (`TokenRefreshSerializer` sólo renueva `jti`, `exp` e `iat`). Dura lo mismo
  que el login, y el logout lo cierra al invalidar el refresh.

Transición
----------
Los tokens emitidos antes de este cambio no llevan `sid`. Para ellos se usa el `jti` del access:
aísla igual (más, incluso), pero el desbloqueo no sobrevive a la siguiente renovación del access
y hay que repetirlo. Desaparece solo cuando caducan esos refresh (7 días).
"""

import uuid

SESSION_CLAIM = 'sid'


def new_login_session_id():
    """Identificador opaco y aleatorio para una sesión de login nueva."""
    return uuid.uuid4().hex


def session_id_from_request(request):
    """Sesión de login de la petición, o `None` si no viene autenticada por JWT.

    `request.auth` es el access token que validó `CookieJWTAuthentication` (por cookie o por
    Bearer)."""
    token = getattr(request, 'auth', None)
    if token is None:
        return None
    return token.get(SESSION_CLAIM) or token.get('jti')
