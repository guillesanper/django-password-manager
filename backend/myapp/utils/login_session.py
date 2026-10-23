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

Terminar un login (N14)
-----------------------
El `sid` es también lo que se revoca desde la pantalla de sesiones. Meter el refresh en la
blacklist no basta: rota en cada renovación y el access sigue valiendo hasta 60 min. Por eso
se guarda el `sid` en `RevokedSession`, y `CookieJWTAuthentication` y
`CookieTokenRefreshView` rechazan cualquier token que lo lleve. Los tokens sin `sid` no se
pueden revocar así.
"""

import uuid
from datetime import timedelta

from django.utils import timezone
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken

SESSION_ID_CLAIM = 'sid'


def stamp_session_id(refresh):
    """Asigna un `sid` nuevo al refresh recién emitido. Llamar ANTES de derivar el access
    (`refresh.access_token`), que es cuando simplejwt copia los claims.

    `RefreshToken.for_user` ya guardó el token en `OutstandingToken` sin el claim; se
    reescribe esa fila con el token que de verdad sale, para que `live_session_ids` encuentre
    el `sid` aunque el login no haya renovado todavía (N14)."""
    refresh[SESSION_ID_CLAIM] = uuid.uuid4().hex
    OutstandingToken.objects.filter(jti=refresh['jti']).update(token=str(refresh))
    return refresh


def session_id_from_request(request):
    """`sid` del token con el que se autenticó la petición, o el `jti` del access si el token
    es anterior al claim. `None` si la petición no trae un JWT validado (quien llama debe tratar
    la bóveda como bloqueada)."""
    token = getattr(request, 'auth', None)
    if token is None or not hasattr(token, 'get'):
        return None
    return token.get(SESSION_ID_CLAIM) or token.get('jti')


def session_id_of(token):
    """`sid` de un token ya validado (access o refresh), o None si es anterior al claim.
    Sin el respaldo al `jti` de `session_id_from_request`: para revocar sólo vale el `sid`."""
    return token.get(SESSION_ID_CLAIM) if hasattr(token, 'get') else None


def is_session_revoked(sid):
    """True si el login `sid` se terminó desde la pantalla de sesiones."""
    from ..models import RevokedSession

    return bool(sid) and RevokedSession.objects.filter(sid=sid).exists()


def revoke_sessions(user, sids):
    """Termina los logins `sids` de `user`: sus access dejan de autenticar y sus refresh de
    renovarse. Idempotente. Purga de paso las filas que ya no pueden casar con ningún token."""
    from ..models import RevokedSession

    now = timezone.now()
    RevokedSession.objects.filter(expires_at__lte=now).delete()
    leeway = api_settings.LEEWAY
    if not isinstance(leeway, timedelta):
        leeway = timedelta(seconds=leeway)
    expires_at = now + api_settings.REFRESH_TOKEN_LIFETIME + leeway
    RevokedSession.objects.bulk_create(
        [RevokedSession(sid=sid, user=user, expires_at=expires_at) for sid in set(sids) if sid],
        ignore_conflicts=True,
    )


def live_session_ids(user):
    """`sid` de todos los logins de `user` con un refresh vivo (sin caducar ni en la
    blacklist), estén o no en la pantalla de sesiones. Con la rotación, cada login tiene
    como mucho uno vivo: los anteriores están en la blacklist."""
    sids = set()
    outstanding = OutstandingToken.objects.filter(
        user=user, expires_at__gt=timezone.now(), blacklistedtoken__isnull=True
    ).only('token')
    for row in outstanding:
        try:
            # Sin verificar: es un token emitido por este servidor y guardado en su BD, y
            # sólo se lee el claim para revocar, nunca para autorizar.
            sid = RefreshToken(row.token, verify=False).get(SESSION_ID_CLAIM)
        except TokenError:
            continue
        if sid:
            sids.add(sid)
    return sids
