"""Emisión y retirada de los JWT como cookies `HttpOnly` (A1, A2).

Punto único donde se decide cómo se escriben las cookies de sesión. Antes los
tokens viajaban en el cuerpo de la respuesta de login y el frontend los
guardaba en `localStorage` y `sessionStorage`; ahora el cuerpo ya no los lleva
y el navegador es el único que los custodia.

Atributos y por qué
-------------------
- `HttpOnly`: el objetivo entero. Sin él, esto sería `localStorage` con más
  pasos.
- `Secure`: atado a `DJANGO_TLS_ENABLED`, igual que el resto de cookies. En
  local sin TLS tiene que ser `False` o el navegador no la guarda y no se
  puede ni entrar.
- `SameSite=Strict`: el navegador no adjunta la cookie en peticiones nacidas
  en otro sitio, lo que corta el CSRF en la raíz. Es defensa en profundidad
  sobre el doble envío de `CookieJWTAuthentication`, no un sustituto: `Strict`
  no lo respetan clientes antiguos y no cubre subdominios comprometidos.
- `path='/'` **también para el refresh**, en lugar de acotarlo a la ruta de
  renovación. Acotarlo sería algo más estrecho, pero entonces `/auth/logout/`
  no recibiría el refresh y el logout no podría invalidar el token *de este
  dispositivo*: tendría que barrer todos los del usuario, que es justo el
  efecto colateral que este paso viene a quitar.

La vida de la cookie se toma de `SIMPLE_JWT`, no de constantes propias, para
que no puedan desincronizarse de la vida real del token.
"""

from django.conf import settings


def _cookie_kwargs():
    return {
        'httponly': True,
        'secure': settings.JWT_AUTH_COOKIE_SECURE,
        'samesite': settings.JWT_AUTH_COOKIE_SAMESITE,
        'path': '/',
    }


def set_auth_cookies(response, access_token, refresh_token=None):
    """Escribe el access (y opcionalmente el refresh) como cookies HttpOnly."""
    response.set_cookie(
        settings.JWT_AUTH_COOKIE,
        str(access_token),
        max_age=int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds()),
        **_cookie_kwargs(),
    )

    if refresh_token is not None:
        response.set_cookie(
            settings.JWT_AUTH_REFRESH_COOKIE,
            str(refresh_token),
            max_age=int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()),
            **_cookie_kwargs(),
        )

    return response


def clear_auth_cookies(response):
    """Borra ambas cookies.

    `delete_cookie` tiene que repetir `path` y `samesite`: el navegador sólo
    sustituye una cookie si coinciden nombre, dominio y path, así que borrarla
    con atributos distintos deja la original viva y el usuario seguiría
    autenticado después de cerrar sesión.
    """
    for name in (settings.JWT_AUTH_COOKIE, settings.JWT_AUTH_REFRESH_COOKIE):
        response.delete_cookie(
            name,
            path='/',
            samesite=settings.JWT_AUTH_COOKIE_SAMESITE,
        )
    return response


def get_refresh_from_cookie(request):
    return request.COOKIES.get(settings.JWT_AUTH_REFRESH_COOKIE)
