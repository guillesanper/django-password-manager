from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from ..authentication import CookieJWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone

from datetime import timedelta
import re
import requests

from ..models import PasswordEntry

import logging

logger = logging.getLogger(__name__)


# Paso 27 — análisis de seguridad ZERO-KNOWLEDGE.
#
# El análisis v1 descifraba la bóveda entera EN EL SERVIDOR con `MasterKey.hashed_key` (C1/C3): un
# oráculo de descifrado. Eso ya no existe: el servidor no puede descifrar. El análisis (entropía,
# duplicados, patrones, fortaleza) se hace EN CLIENTE sobre las entradas descifradas en memoria
# (frontend/src/services/passwordAnalysis.ts). Los dos endpoints legados (`/analysis/`,
# `/check-breach/`) se RETIRARON: no tienen sustituto server-side.
#
# Lo único que el navegador no puede hacer por la CSP (`connect-src 'self'`) es llamar a HIBP, así
# que queda un PROXY k-anonimato: `api_hibp_range` recibe SÓLO un prefijo SHA-1 de 5 hex, relega la
# range-query a HIBP y devuelve la lista de sufijos. El servidor nunca ve la contraseña ni el hash
# completo; no descifra nada (no es oráculo). `api_security_recommendations` sigue vivo y sólo usa
# metadatos (fechas), sin descifrar.


_HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
_PREFIX_RE = re.compile(r'^[0-9A-Fa-f]{5}$')


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_hibp_range(request, prefix):
    """Proxy k-anonimato a HaveIBeenPwned (paso 27).

    Recibe un prefijo SHA-1 de 5 caracteres hex; el navegador calcula `SHA1(password)`, envía sólo
    el prefijo y compara el sufijo EN LOCAL. El servidor jamás ve la contraseña ni el hash completo
    (modelo k-anonimato de HIBP), así que no es un oráculo de descifrado (a diferencia de C3).

    Es un **GET**, por lo que el middleware lo clasifica como `normal` (sin el rate limit de la
    maestra); aun así requiere sesión. Sin SSRF: el host es fijo y el prefijo se valida a 5 hex.
    """
    if not _PREFIX_RE.match(prefix or ''):
        return JsonResponse({'success': False, 'error': 'Prefijo inválido'}, status=400)

    prefix = prefix.upper()
    try:
        # `Add-Padding: true`: HIBP rellena la respuesta para que su longitud no filtre cuántos
        # sufijos comparten el prefijo. Las líneas de relleno traen count 0 y no afectan a la
        # comparación (el sufijo real llega con su count real).
        resp = requests.get(
            _HIBP_RANGE_URL.format(prefix),
            timeout=5,
            headers={'Add-Padding': 'true', 'User-Agent': 'gestor-contrasenas-zk'},
        )
    except requests.RequestException:
        logger.warning("No se pudo consultar HIBP para el prefijo %s", prefix)
        return JsonResponse(
            {'success': False, 'error': 'No se pudo consultar el servicio de filtraciones'},
            status=502,
        )

    if resp.status_code != 200:
        return JsonResponse(
            {'success': False, 'error': 'Servicio de filtraciones no disponible'},
            status=502,
        )

    return JsonResponse({'success': True, 'prefix': prefix, 'ranges': resp.text})


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_security_recommendations(request):
    """
    Recomendaciones personalizadas de seguridad.

    Sólo usa metadatos que el servidor conoce sin descifrar (número de entradas y fechas). El
    análisis del contenido de las contraseñas se hace en cliente (paso 27).
    """
    try:
        password_entries = PasswordEntry.objects.filter(user=request.user)
        total_passwords = password_entries.count()

        if total_passwords == 0:
            return JsonResponse({
                'success': True,
                'recommendations': [
                    {
                        'type': 'getting_started',
                        'priority': 'high',
                        'title': 'Comienza a usar el gestor',
                        'description': 'Agrega tus primeras contraseñas para obtener análisis de seguridad personalizado',
                        'action': 'add_password'
                    }
                ]
            })

        recommendations = []

        # Contraseñas antiguas (metadato, no requiere descifrar)
        old_passwords = password_entries.filter(
            updated_at__lt=timezone.now() - timedelta(days=365)
        ).count()

        if old_passwords > 0:
            recommendations.append({
                'type': 'update_old_passwords',
                'priority': 'medium',
                'title': 'Actualizar contraseñas antiguas',
                'description': f'Tienes {old_passwords} contraseñas que no se han actualizado en más de un año',
                'action': 'update_passwords',
                'count': old_passwords
            })

        # Recomendación general de seguridad
        if total_passwords < 5:
            recommendations.append({
                'type': 'expand_usage',
                'priority': 'low',
                'title': 'Expande el uso del gestor',
                'description': 'Considera migrar más cuentas al gestor de contraseñas para mayor seguridad',
                'action': 'add_more_passwords'
            })

        return JsonResponse({
            'success': True,
            'recommendations': recommendations
        })

    except Exception:
        logger.exception("Error obteniendo recomendaciones")
        return JsonResponse({
            'success': False,
            'error': 'Error al obtener recomendaciones'
        }, status=500)
