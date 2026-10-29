"""Registro en dos pasos con verificación del email (N17, AU-08).

El problema que resuelve
------------------------
El alta respondía "Ya existe una cuenta con este email": un oráculo de existencia de cuentas
(A6 sólo se había cerrado en el login). Y no hay forma de ocultarlo mientras el alta cree la
cuenta en el acto, porque el 200 de un alta nueva ya dice que el email estaba libre. Además
quien registraba un email ajeno quedaba dentro sin demostrar que lo controla (M9).

Cómo funciona
-------------
1. `request_registration` no crea nada en `auth_user`. Si el email está libre guarda un
   `PendingRegistration` y manda un enlace de activación; si ya tiene cuenta manda un aviso.
   Quien llama responde lo mismo en ambos casos, y los dos caminos cuestan lo mismo: un hash
   de la contraseña y un correo.
2. `confirm_registration` crea la cuenta con el token del enlace Y la contraseña del alta.
   Pedir la contraseña evita que alguien dé de alta un email ajeno con una contraseña suya y
   el dueño, al pulsar el enlace que le llega, le active la cuenta.

El token va en el fragmento (`#token=`), que el navegador no manda al servidor: no acaba en
los logs de nginx ni en un `Referer`. En la base sólo se guarda su SHA-256.
"""

import hashlib
import logging
import re
import secrets
import time
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from ..models import PendingRegistration
from .cache_utils import strict_get, strict_set

auth_logger = logging.getLogger('auth')

TOKEN_TTL = timedelta(hours=24)
MAX_CONFIRM_FAILURES = 5        # contraseñas erróneas antes de descartar el alta pendiente
MAX_EMAILS_PER_ADDRESS = 5      # correos por dirección y hora: que nadie inunde un buzón ajeno
EMAILS_WINDOW = 3600


class EmailDeliveryError(Exception):
    """No se pudo mandar el correo. Le pasa igual a un email libre que a uno registrado."""


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _take_email_slot(email):
    """¿Queda cupo de correos para esta dirección en la última hora? Lo consume si queda.

    Política de caché: STRICT. Sin caché no hay tope y el alta serviría para inundar
    buzones; el registro ya falla cerrado por su propio límite por IP.
    """
    key = f"registration_emails_{email}"
    now = time.time()
    sent = [t for t in strict_get(key, []) if now - t < EMAILS_WINDOW]
    if len(sent) >= MAX_EMAILS_PER_ADDRESS:
        return False
    sent.append(now)
    strict_set(key, sent, EMAILS_WINDOW)
    return True


def _send(email, subject, body):
    try:
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [email])
    except Exception as exc:
        auth_logger.error("No se pudo enviar el correo de registro: %s", type(exc).__name__)
        raise EmailDeliveryError from exc


def request_registration(*, email, first_name, last_name, password):
    """Primer paso del alta. No devuelve nada que dependa de si el email existe.

    Lanza `EmailDeliveryError` si el correo no sale, también en ambos casos. Pasado el tope de
    correos de la dirección no hace nada, en silencio.
    """
    # El hash va primero y en los dos caminos: es lo que más cuesta (Argon2) y si sólo lo
    # pagase el alta nueva, el tiempo de respuesta delataría al email registrado.
    password_hash = make_password(password)
    PendingRegistration.objects.filter(expires_at__lte=timezone.now()).delete()

    if not _take_email_slot(email):
        auth_logger.warning("Tope de correos de registro alcanzado para una dirección")
        return

    if User.objects.filter(email__iexact=email).exists():
        _send(
            email,
            "Ya tienes una cuenta en PasswordManager",
            "Alguien ha intentado crear una cuenta con este correo, pero ya tienes una.\n\n"
            f"Si has sido tú, inicia sesión en {settings.PUBLIC_URL}/login\n\n"
            "Si no, puedes ignorar este mensaje: no se ha cambiado nada.\n",
        )
        return

    token = secrets.token_urlsafe(32)
    # Si el correo no sale, el alta no queda pendiente: la transacción la deshace.
    with transaction.atomic():
        PendingRegistration.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=password_hash,
            token_hash=_hash_token(token),
            expires_at=timezone.now() + TOKEN_TTL,
        )
        _send(
            email,
            "Activa tu cuenta de PasswordManager",
            f"Hola, {first_name}:\n\n"
            "Para terminar de crear tu cuenta, abre este enlace e introduce la contraseña "
            "que elegiste al registrarte:\n\n"
            f"{settings.PUBLIC_URL}/verificar-email#token={token}\n\n"
            "El enlace caduca en 24 horas. Si no has sido tú, ignora este mensaje: "
            "sin la contraseña nadie puede activar la cuenta.\n",
        )


def confirm_registration(token, password):
    """Segundo paso: crea la cuenta. Devuelve `(user, None)` o `(None, motivo)`.

    `motivo` es 'invalid' (token inexistente, caducado o ya usado, o el email ya tiene
    cuenta) o 'password' (la contraseña no es la del alta).
    """
    found = PendingRegistration.objects.filter(
        token_hash=_hash_token(token), expires_at__gt=timezone.now()
    ).values_list('email', flat=True).first()
    if found is None:
        return None, 'invalid'

    with transaction.atomic():
        # Se bloquean TODAS las altas de ese email: dos confirmaciones a la vez (dos enlaces
        # distintos) no pueden crear dos cuentas. La segunda espera aquí y, al seguir, ya no
        # encuentra su fila.
        locked = list(
            PendingRegistration.objects.select_for_update().filter(email=found).order_by('id')
        )
        pending = next((p for p in locked if p.token_hash == _hash_token(token)), None)
        if pending is None or pending.expires_at <= timezone.now():
            return None, 'invalid'

        if not check_password(password, pending.password_hash):
            pending.failed_attempts += 1
            if pending.failed_attempts >= MAX_CONFIRM_FAILURES:
                pending.delete()
            else:
                pending.save(update_fields=['failed_attempts'])
            return None, 'password'

        if User.objects.filter(email__iexact=pending.email).exists():
            PendingRegistration.objects.filter(email=pending.email).delete()
            return None, 'invalid'

        user = User(
            username=generate_unique_username(pending.email),
            email=pending.email,
            first_name=pending.first_name,
            last_name=pending.last_name,
            password=pending.password_hash,
        )
        user.save()
        PendingRegistration.objects.filter(email=pending.email).delete()
    return user, None


def generate_unique_username(email):
    """Username único a partir de la parte local del email."""
    base_username = re.sub(r'[^a-zA-Z0-9]', '', email.split('@')[0])
    if len(base_username) < 3:
        base_username = 'user'

    username = base_username
    counter = 1
    while User.objects.filter(username=username).exists():
        username = f"{base_username}{counter}"
        counter += 1

        # Prevenir loop infinito
        if counter > 1000:
            username = f"user{int(time.time())}"
            break

    return username
