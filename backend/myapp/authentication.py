# myapp/authentication.py - Backend personalizado para autenticación por email
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.db.models import Q
from django.middleware.csrf import CsrfViewMiddleware

from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication


class _CSRFCheck(CsrfViewMiddleware):
    """`CsrfViewMiddleware` que devuelve el motivo del rechazo en vez de un 403.

    `CSRFCheck` NO es importable desde `django.middleware.csrf` (es un detalle
    interno que cambia entre versiones; en Django 5.1 no existe). El patrón
    soportado —y el que usa el propio `SessionAuthentication` de DRF— es
    subclasear `CsrfViewMiddleware` y sobreescribir `_reject` para que
    `process_view` devuelva el motivo como cadena en lugar de una respuesta,
    dejando que quien llama decida qué hacer.
    """
    def _reject(self, request, reason):
        return reason


def enforce_csrf(request):
    """Aplica la comprobación CSRF de Django a una petición de DRF.

    Es el mismo código que usa `SessionAuthentication` de DRF. Hace falta
    porque las vistas de DRF se despachan con `csrf_exempt`: el
    `CsrfViewMiddleware` global no llega a mirarlas, y la comprobación tiene
    que hacerla la clase de autenticación.

    Levanta `PermissionDenied` (403) si falla. Los métodos seguros
    (GET/HEAD/OPTIONS/TRACE) los deja pasar el propio `process_view`.

    Opera sobre la request de Django SUBYACENTE (`request._request`), nunca
    sobre la de DRF. `CsrfViewMiddleware._check_token` accede a `request.POST`;
    sobre la Request de DRF eso dispara el parseo del cuerpo y **consume el
    stream**, de modo que la vista, al hacer luego `json.loads(request.body)`,
    revienta con `RawPostDataException` (un 500). Sobre la request de Django, en
    cambio, `request.POST` con `Content-Type: application/json` NO lee el
    stream (devuelve un QueryDict vacío), el token CSRF se lee de la cabecera
    `X-CSRFToken`, y el cuerpo queda intacto para la vista.
    """
    django_request = getattr(request, '_request', request)

    def dummy_get_response(_request):
        return None

    check = _CSRFCheck(dummy_get_response)
    check.process_request(django_request)
    reason = check.process_view(django_request, None, (), {})
    if reason:
        raise exceptions.PermissionDenied(f'CSRF Failed: {reason}')


class CookieJWTAuthentication(JWTAuthentication):
    """Autenticación JWT que lee el access token de una cookie `HttpOnly` (A1, A2).

    Por qué la cookie y no `localStorage`
    -------------------------------------
    El access y el refresh (7 días) vivían en `localStorage` **y** en
    `sessionStorage`, ambos legibles desde JavaScript. Con eso, cualquier XSS
    —y no había CSP que lo estorbara— se llevaba la sesión entera durante una
    semana, no la petición en curso. Una cookie `HttpOnly` no la puede leer el
    JavaScript de la página: el navegador la adjunta y punto.

    El precio: CSRF
    ---------------
    Ese es justo el motivo por el que la cabecera `Authorization` era inmune a
    CSRF. Una cabecera hay que ponerla a propósito; una cookie la adjunta el
    navegador **también cuando la petición la origina un tercero**. Por eso,
    cuando el token viene de la cookie, aquí se exige el token CSRF de doble
    envío (cookie `csrftoken` legible + cabecera `X-CSRFToken`), que es lo que
    un sitio ajeno no puede reproducir.

    Se conserva el camino de `Authorization: Bearer`
    -----------------------------------------------
    Si la petición trae la cabecera, se delega en el comportamiento original y
    **no** se exige CSRF: una cabecera no se adjunta sola, así que no hay nada
    que falsificar. Esto mantiene utilizables curl, los scripts de verificación
    y cualquier cliente que no sea un navegador. No reabre A1: lo que cerraba
    A1 es que el frontend deje de guardar el token donde el JavaScript lo lee,
    no que el servidor deje de aceptar la cabecera.
    """

    def authenticate(self, request):
        if self.get_header(request) is not None:
            return super().authenticate(request)

        raw_token = request.COOKIES.get(settings.JWT_AUTH_COOKIE)
        if not raw_token:
            return None

        validated_token = self.get_validated_token(raw_token)
        enforce_csrf(request)
        return self.get_user(validated_token), validated_token

class EmailBackend(ModelBackend):
    """
    Backend de autenticación personalizado que permite login con email o username
    """

    def authenticate(self, request, username=None, password=None, email=None, **kwargs):
        # Sin contraseña no hay nada que comparar, y la decisión no depende de
        # si el usuario existe, así que salir aquí no filtra nada.
        if password is None:
            return None

        try:
            # Si se proporciona email directamente, usarlo
            if email:
                user = User.objects.get(email=email)
            # Si no, intentar con username que puede ser email o username
            elif username:
                # Intentar encontrar por email primero, luego por username
                user = User.objects.get(Q(email=username) | Q(username=username))
            else:
                return None

            # Verificar la contraseña
            if user.check_password(password):
                return user
            else:
                return None

        except User.DoesNotExist:
            self.run_dummy_hasher(password)
            return None
        except User.MultipleObjectsReturned:
            # Si hay múltiples usuarios, intentar con el email exacto
            try:
                if email:
                    user = User.objects.get(email=email)
                elif username and '@' in username:
                    user = User.objects.get(email=username)
                else:
                    user = User.objects.get(username=username)

                if user.check_password(password):
                    return user
            except User.DoesNotExist:
                self.run_dummy_hasher(password)

            return None

    def run_dummy_hasher(self, password):
        """Ejecuta el hasher una vez sobre un usuario que no existe (A6).

        Sin esto, la rama `User.DoesNotExist` retornaba de inmediato mientras
        que la de un email existente pagaba el coste del hasher —por diseño,
        decenas de milisegundos—. La diferencia es medible desde fuera y
        convierte el login en un oráculo de existencia de cuentas: se prueba una
        lista de correos, se cronometra, y los rápidos son los que no están
        registrados. Con eso se arma una lista para phishing dirigido, que en un
        gestor de contraseñas es el ataque que de verdad importa.

        Es la misma contramedida que `ModelBackend` implementa (ticket #20760 de
        Django) y que esta subclase perdía al sobrescribir `authenticate`.

        El coste se iguala solo, sin constantes que ajustar: `set_password` usa
        el primer hasher de `PASSWORD_HASHERS`, que es el mismo con el que se
        guardó la contraseña del usuario que sí existe.
        """
        User().set_password(password)

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
