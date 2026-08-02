"""
General application views - main app view, settings, user management, metrics
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework.permissions import IsAuthenticated,AllowAny
from ..authentication import CookieJWTAuthentication
from django.http import JsonResponse, HttpResponse, HttpResponseNotFound
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.utils import timezone

import ipaddress
import re
import socket
import requests

from ..models import UserSettings
from ..forms import SettingsForm

import logging

logger = logging.getLogger(__name__)


# ==========================================
# MAIN APP VIEW FOR REACT SPA
# ==========================================

def app_view(request, path=''):
    """
    Main view for the SPA that handles all frontend routes.
    Accepts an optional path parameter for catch-all.
    """
    # If it's a request for metrics, return Prometheus metrics
    if path == 'metrics' or request.path == '/metrics':
        return metrics_view(request)

    # El catch-all sirve la SPA para el enrutado en cliente, pero NUNCA debe
    # tragarse la API (G3, generaliza N1): toda ruta /api/ real se registra antes
    # del catch-all, así que una /api/ que llega hasta aquí sencillamente no
    # existe. Devolver la SPA con 200-HTML enmascara ese 404 y hace que el cliente
    # reciba HTML donde espera JSON (justo el fallo que N1 cerró para una ruta
    # concreta; aquí se cierra para cualquier /api/ desconocida).
    if request.path.startswith('/api/'):
        return JsonResponse({'error': 'Not found'}, status=404)

    # For any other route, serve the SPA
    return render(request, 'base.html')


# ==========================================
# USER SETTINGS
# ==========================================

@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_user_settings(request):
    """API for user settings"""
    settings_obj, created = UserSettings.objects.get_or_create(user=request.user)
    data = {
        'theme': settings_obj.theme,
        'require_password_modify': settings_obj.require_password_modify,
        'require_password_delete': settings_obj.require_password_delete,
        'notifications': settings_obj.notifications
    }
    return JsonResponse(data)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def settings_view(request):
    """Settings view"""
    user_settings, created = UserSettings.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = SettingsForm(request.POST, instance=user_settings)
        if form.is_valid():
            form.save()
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'message': 'Settings updated successfully'})
            messages.success(request, 'Configuraciones actualizadas correctamente.')
            return redirect('app')
        else:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': 'Form validation failed', 'errors': form.errors}, status=400)
            messages.error(request, 'Hubo un error al actualizar las configuraciones.')
    
    return app_view(request)


# ==========================================
# UTILITY APIs
# ==========================================

# Límites del generador (Fase 1, paso 17 — M3). `MAX_PASSWORD_LENGTH` coincide a
# propósito con el `max="128"` del deslizante de PasswordGeneratorPage.tsx, y
# `MIN_PASSWORD_LENGTH` con su `min="8"`: así ninguna petición que la interfaz
# pueda originar es rechazada.
MIN_PASSWORD_COUNT = 1
MAX_PASSWORD_COUNT = 20
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def _bounded_int(raw, default, minimum, maximum, name):
    """Convierte un parámetro de query en un entero dentro de [minimum, maximum].

    Lanza `ValueError` con un mensaje ya apto para el cliente: sólo repite el
    nombre del parámetro y sus límites, que no son información sensible.
    """
    if raw is None or raw == '':
        return default

    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError(f"El parámetro '{name}' debe ser un número entero.")

    if not minimum <= value <= maximum:
        raise ValueError(
            f"El parámetro '{name}' debe estar entre {minimum} y {maximum}."
        )

    return value


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_password_generator(request):
    """API for password generation.

    Los límites no son cosmética (M3): el coste del generador es
    `count * length` llamadas a `secrets.randbelow` más una cadena de ese
    tamaño en memoria. Sin acotar, `?count=100000&length=100000` bloquea un
    worker de gunicorn durante un tiempo arbitrario, y bastan tres peticiones
    —una por worker— para dejar la aplicación entera sin servicio. El `int()`
    sin proteger tampoco era inocuo: `?count=abc` reventaba con un `ValueError`
    no capturado, es decir un 500 en vez de un 400.
    """
    try:
        count = _bounded_int(
            request.GET.get('count'), 5,
            MIN_PASSWORD_COUNT, MAX_PASSWORD_COUNT, 'count',
        )
        length = _bounded_int(
            request.GET.get('length'), 20,
            MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH, 'length',
        )
    except ValueError as e:
        # Única excepción deliberada a la regla de M1: el `try` sólo envuelve a
        # `_bounded_int`, que levanta `ValueError` con un texto redactado para
        # el cliente (nombre del parámetro y límites, nada interno). No es la
        # excepción de terceros la que se está reenviando.
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

    use_special = request.GET.get('special', 'true').lower() == 'true'
    use_numbers = request.GET.get('numbers', 'true').lower() == 'true'

    from ..encryption_utils import generate_passwords
    passwords = generate_passwords(count, length, use_special, use_numbers)
    return JsonResponse({'passwords': passwords})


# ==========================================
# METRICS
# ==========================================

def metrics_view(request):
    """
    View to serve Prometheus metrics.
    """
    try:
        user_count = User.objects.count()
        
        metrics_data = f"""
# HELP django_users_total Total number of users
# TYPE django_users_total gauge
django_users_total {user_count}

# HELP django_db_connections Database connections
# TYPE django_db_connections gauge
django_db_connections {len(connection.queries) if connection.queries else 0}
"""
        
        return HttpResponse(
            metrics_data, 
            content_type='text/plain; version=0.0.4; charset=utf-8'
        )
    except Exception:
        logger.exception("Error generando métricas Prometheus")
        return HttpResponse(
            "# Error generating metrics\n",
            content_type='text/plain; version=0.0.4; charset=utf-8',
            status=500
        )
        
        
# Vista de health check simple
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Simple health check endpoint"""
    return JsonResponse({
        'status': 'ok',
        'timestamp': timezone.now().isoformat()
    })


# ==========================================
# PROXY DE FAVICON (sustituye la dependencia de www.google.com)
# ==========================================
#
# El frontend pintaba el icono de cada sitio desde `https://www.google.com/s2/favicons`, lo que
# (a) revelaba a Google el dominio de cada cuenta y (b) obligaba a abrir `img-src` a un host
# externo —un canal de exfiltración si hubiera un XSS—. Este proxy lo trae a `img-src 'self'`:
# el navegador pide `/api/favicon/<dominio>/`, el servidor descarga el favicon del propio sitio y
# lo devuelve cacheado. NO hay terceros: sólo el servidor y el sitio de destino.
#
# COSTE ZERO-KNOWLEDGE asumido a conciencia: el `website` de cada cuenta va cifrado en el blob, así
# que hasta ahora el servidor no sabía a qué sitios tienes cuentas. Con este proxy, el servidor ve
# el dominio en la petición del favicon (nunca lo persiste, sólo lo usa para la descarga y la caché
# por dominio). Es el compromiso elegido: icono real a cambio de que el servidor aprenda dominios.
#
# SSRF: el `<domain>` lo controla el usuario, así que antes de descargar nada se valida el formato
# de host (rechaza literales IP), se resuelve por DNS y se rechaza si CUALQUIER IP resuelta es
# privada/loopback/link-local/reservada (bloquea 127.0.0.1, 169.254.169.254 —metadata de nube—,
# 10./192.168./172.16, ::1…). No se siguen redirecciones (evita el bypass por 3xx a un host
# interno) y sólo se acepta un 200 con `Content-Type: image/*`, con tope de tamaño.

_FAVICON_HOST_RE = re.compile(
    r'^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$'
)
_FAVICON_MAX_BYTES = 200 * 1024  # 200 KiB: un favicon legítimo nunca se acerca a esto
_FAVICON_ALLOWED_CT = (
    'image/x-icon', 'image/vnd.microsoft.icon', 'image/png', 'image/gif',
    'image/jpeg', 'image/webp', 'image/svg+xml',
)
_FAVICON_TTL = 60 * 60 * 24 * 7   # 7 días en caché los aciertos
_FAVICON_NEG_TTL = 60 * 60 * 6    # 6 h los fallos, para no martillear sitios sin favicon


def _favicon_host_is_public(host):
    """True sólo si `host` resuelve y TODAS sus IPs son públicas (anti-SSRF)."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_favicon(request, domain):
    """Proxy de favicon: descarga `https://<domain>/favicon.ico` y lo devuelve cacheado.

    Devuelve 404 (vacío) ante cualquier problema —dominio inválido, host no público, sin favicon,
    tipo no imagen— y el frontend cae a su icono genérico vía `onError`. Sólo para usuarios
    autenticados; la respuesta lleva `nosniff` y caché de navegador.
    """
    domain = (domain or '').strip().lower().rstrip('.')
    if not _FAVICON_HOST_RE.match(domain):
        return HttpResponseNotFound()

    cache_key = f'favicon:v1:{domain}'
    cached = cache.get(cache_key)
    if cached is not None:
        if cached == b'':  # negativo cacheado
            return HttpResponseNotFound()
        content, content_type = cached
        return _favicon_response(content, content_type)

    if not _favicon_host_is_public(domain):
        cache.set(cache_key, b'', _FAVICON_NEG_TTL)
        return HttpResponseNotFound()

    try:
        resp = requests.get(
            f'https://{domain}/favicon.ico',
            timeout=5,
            stream=True,
            allow_redirects=False,  # no seguir 3xx: evita el bypass SSRF por redirección
            headers={'User-Agent': 'gestor-contrasenas-favicon'},
        )
    except requests.RequestException:
        cache.set(cache_key, b'', _FAVICON_NEG_TTL)
        return HttpResponseNotFound()

    content_type = resp.headers.get('Content-Type', '').split(';')[0].strip().lower()
    if resp.status_code != 200 or content_type not in _FAVICON_ALLOWED_CT:
        resp.close()
        cache.set(cache_key, b'', _FAVICON_NEG_TTL)
        return HttpResponseNotFound()

    # Lectura con tope: si el cuerpo supera el límite, se descarta (favicon anómalo).
    content = b''
    for chunk in resp.iter_content(8192):
        content += chunk
        if len(content) > _FAVICON_MAX_BYTES:
            resp.close()
            cache.set(cache_key, b'', _FAVICON_NEG_TTL)
            return HttpResponseNotFound()
    resp.close()

    if not content:
        cache.set(cache_key, b'', _FAVICON_NEG_TTL)
        return HttpResponseNotFound()

    cache.set(cache_key, (content, content_type), _FAVICON_TTL)
    return _favicon_response(content, content_type)


def _favicon_response(content, content_type):
    response = HttpResponse(content, content_type=content_type)
    # `nosniff` impide que el navegador reinterprete los bytes como HTML; el favicon sólo se
    # carga vía <img>, contexto en el que ni un SVG ejecuta script.
    response['X-Content-Type-Options'] = 'nosniff'
    response['Cache-Control'] = 'private, max-age=86400'  # 1 día en el navegador
    return response