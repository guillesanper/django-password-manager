from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from ..authentication import CookieJWTAuthentication
import json
from ..models import UserCrypto
from ..utils.master_key_guard import guard_auth_key

import logging

logger = logging.getLogger(__name__)


# ==========================================
# VISTAS PARA MANEJO DE CLAVE MAESTRA (Fase 2, zero-knowledge)
# ==========================================
#
# El servidor NUNCA recibe la contraseña maestra. El cliente deriva en local (crypto.ts):
#   MK = Argon2id(master_password, kdf_salt) → AuthKey = HKDF(MK,"auth"), EncKey = HKDF(MK,"enc")
# y envía sólo material opaco: kdf_salt, kdf_params, auth_key (para hashear) y wrapped_vault_key.
# El servidor guarda Argon2id(AuthKey) y devuelve el material de desbloqueo cuando se le pide.


def _require_fields(data, fields):
    """Devuelve el nombre del primer campo ausente/vacío, o None si están todos."""
    for f in fields:
        if not data.get(f):
            return f
    return None


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def setup_master_key(request):
    """Registra el material criptográfico zero-knowledge del usuario (primera vez).

    Espera el resultado de `setupUserCrypto` en el cliente:
        { kdf_salt, kdf_params, auth_key, wrapped_vault_key, crypto_version }
    """
    try:
        data = json.loads(request.body)

        missing = _require_fields(data, ['kdf_salt', 'auth_key', 'wrapped_vault_key'])
        if missing:
            return JsonResponse({
                'success': False,
                'error': f'Falta el campo requerido: {missing}',
            }, status=400)

        kdf_params = data.get('kdf_params') or {}
        if not isinstance(kdf_params, dict):
            return JsonResponse({
                'success': False,
                'error': 'kdf_params debe ser un objeto',
            }, status=400)

        if UserCrypto.objects.filter(user=request.user).exists():
            return JsonResponse({
                'success': False,
                'error': 'Ya tienes una clave maestra configurada',
            }, status=400)

        user_crypto = UserCrypto(
            user=request.user,
            kdf_salt=data['kdf_salt'],
            kdf_params=kdf_params,
            wrapped_vault_key=data['wrapped_vault_key'],
            crypto_version=int(data.get('crypto_version', UserCrypto.CURRENT_CRYPTO_VERSION)),
        )
        user_crypto.set_auth_key(data['auth_key'])
        user_crypto.save()

        return JsonResponse({
            'success': True,
            'message': 'Clave maestra configurada exitosamente',
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'}, status=400)
    except Exception:
        logger.exception("Error configurando clave maestra")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def check_master_key(request):
    """Indica si el usuario ya tiene material criptográfico configurado."""
    try:
        has_master_key = UserCrypto.objects.filter(user=request.user).exists()
        return JsonResponse({'success': True, 'hasMasterKey': has_master_key})
    except Exception:
        logger.exception("Error verificando clave maestra")
        return JsonResponse({
            'success': False,
            'error': 'Error al verificar la clave maestra',
        }, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_crypto_params(request):
    """Devuelve el material que el cliente necesita para desbloquear la bóveda en local.

    `wrapped_vault_key` es opaco sin la EncKey (derivada de la maestra), así que devolverlo al
    propio usuario autenticado no filtra nada: sólo su contraseña maestra puede desenvolverlo.
    """
    try:
        try:
            uc = UserCrypto.objects.get(user=request.user)
        except UserCrypto.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No tienes una clave maestra configurada',
            }, status=404)

        return JsonResponse({
            'success': True,
            'kdf_salt': uc.kdf_salt,
            'kdf_params': uc.kdf_params,
            'wrapped_vault_key': uc.wrapped_vault_key,
            'crypto_version': uc.crypto_version,
        })
    except Exception:
        logger.exception("Error obteniendo parámetros criptográficos")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_master_key(request):
    """Prueba de posesión de la maestra: el cliente envía la AuthKey derivada en local.

    Espera { auth_key }. El servidor comprueba Argon2id(AuthKey) bajo el bloqueo exponencial
    por usuario (guard_auth_key). No sirve para desbloquear (eso es local con la EncKey); sirve
    para confirmar la maestra en flujos que lo pidan, sin ser un oráculo de descifrado.
    """
    try:
        data = json.loads(request.body)
        auth_key = data.get('auth_key')

        if not auth_key:
            return JsonResponse({
                'success': False,
                'error': 'La clave de autenticación es requerida',
            }, status=400)

        try:
            uc = UserCrypto.objects.get(user=request.user)
        except UserCrypto.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No tienes una clave maestra configurada',
            }, status=400)

        denial = guard_auth_key(request.user, uc, auth_key)
        if denial is not None:
            return denial

        return JsonResponse({'success': True, 'message': 'Clave maestra válida'})

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'}, status=400)
    except Exception:
        logger.exception("Error verificando clave maestra")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def change_master_key(request):
    """Rotación de la clave maestra (M8). Implementación completa en el paso 25.

    En zero-knowledge rotar es re-envolver la VaultKey con la EncKey nueva (en el cliente,
    `rotateMasterPassword`) y reemplazar el material de UserCrypto — sin re-cifrar la bóveda.
    """
    return JsonResponse({
        'success': False,
        'error': 'Cambio de clave maestra aún no disponible (paso 25).',
        'code': 'FEATURE_PENDING',
    }, status=501)
