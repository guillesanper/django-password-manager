"""
General application views - main app view, settings, user management, metrics
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework.permissions import IsAuthenticated,AllowAny
from ..authentication import CookieJWTAuthentication
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.models import User
from django.db import connection
from django.utils import timezone


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