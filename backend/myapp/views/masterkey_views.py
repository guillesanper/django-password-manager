from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
import json
from ..models import MasterKey

# ==========================================
# VISTAS PARA MANEJO DE CLAVE MAESTRA
# ==========================================

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def setup_master_key(request):
    """Configurar la clave maestra del usuario"""
    try:
        data = json.loads(request.body)
        master_key = data.get('master_key')
        
        if not master_key:
            return JsonResponse({
                'success': False,
                'error': 'La clave maestra es requerida'
            }, status=400)
        
        if len(master_key) < 12:
            return JsonResponse({
                'success': False,
                'error': 'La clave maestra debe tener al menos 12 caracteres'
            }, status=400)
        
        # Verificar si ya tiene una clave maestra
        master_key_entry, created = MasterKey.objects.get_or_create(user=request.user)
        
        if not created and master_key_entry.hashed_key:
            return JsonResponse({
                'success': False,
                'error': 'Ya tienes una clave maestra configurada'
            }, status=400)
        
        # Configurar la clave maestra
        derived_key = master_key_entry.set_master_key(master_key)
        
        if derived_key is None:
            return JsonResponse({
                'success': False,
                'error': 'Error al procesar la clave maestra'
            }, status=500)
        
        return JsonResponse({
            'success': True,
            'message': 'Clave maestra configurada exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error configurando clave maestra: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_master_key(request):
    """Verificar si el usuario ya tiene una clave maestra configurada"""
    try:
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            has_master_key = bool(master_key_entry.hashed_key)
        except MasterKey.DoesNotExist:
            has_master_key = False
        
        return JsonResponse({
            'success': True,
            'hasMasterKey': has_master_key
        })
        
    except Exception as e:
        print(f"Error verificando clave maestra: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error al verificar la clave maestra'
        }, status=500)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def verify_master_key(request):
    """Verificar una clave maestra"""
    try:
        data = json.loads(request.body)
        master_key = data.get('master_key')
        
        if not master_key:
            return JsonResponse({
                'success': False,
                'error': 'La clave maestra es requerida'
            }, status=400)
        
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No tienes una clave maestra configurada'
            }, status=400)
        
        is_valid = master_key_entry.verify_master_key(master_key)
        
        if is_valid:
            return JsonResponse({
                'success': True,
                'message': 'Clave maestra válida'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Clave maestra incorrecta'
            }, status=400)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error verificando clave maestra: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def change_master_key(request):
    """Cambiar la clave maestra del usuario"""
    try:
        data = json.loads(request.body)
        current_master_key = data.get('current_master_key')
        new_master_key = data.get('new_master_key')
        
        if not current_master_key or not new_master_key:
            return JsonResponse({
                'success': False,
                'error': 'Se requieren tanto la clave actual como la nueva'
            }, status=400)
        
        if len(new_master_key) < 12:
            return JsonResponse({
                'success': False,
                'error': 'La nueva clave maestra debe tener al menos 12 caracteres'
            }, status=400)
        
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No tienes una clave maestra configurada'
            }, status=400)
        
        # Verificar la clave actual
        if not master_key_entry.verify_master_key(current_master_key):
            return JsonResponse({
                'success': False,
                'error': 'La clave maestra actual es incorrecta'
            }, status=400)
        
        # IMPORTANTE: Cambiar la clave maestra requeriría re-encriptar todas las contraseñas
        # y archivos del usuario. Esto es una operación compleja que requiere:
        # 1. Desencriptar todas las contraseñas con la clave actual
        # 2. Re-encriptarlas con la nueva clave
        # 3. Actualizar todas las entradas en la base de datos
        
        # Por ahora, retornamos un mensaje indicando que la funcionalidad está en desarrollo
        return JsonResponse({
            'success': False,
            'error': 'Cambio de clave maestra no implementado. Esta funcionalidad requiere re-encriptar todos tus datos.'
        }, status=501)
        
        # TODO: Implementar la lógica completa de cambio de clave maestra
        # La implementación completa sería:
        """
        # 1. Obtener todas las contraseñas del usuario
        passwords = PasswordEntry.objects.filter(user=request.user)
        files = EncryptedFile.objects.filter(user=request.user)
        
        # 2. Desencriptar y re-encriptar cada contraseña
        for password_entry in passwords:
            # Desencriptar con clave actual
            decrypted = decrypt_password(
                password_entry.encrypted_password,
                password_entry.encrypted_key,
                password_entry.iv_or_nonce,
                master_key_entry.hashed_key.encode(),
                password_entry.salt,
                password_entry.encryption_algorithm
            )
            
            # Re-encriptar con nueva clave
            new_master_key_derived = master_key_entry.derive_master_key(new_master_key)
            encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
                decrypted.decode('utf-8'), 
                new_master_key_derived, 
                password_entry.encryption_algorithm
            )
            
            # Actualizar entrada
            password_entry.encrypted_password = encrypted_password
            password_entry.encrypted_key = encrypted_key
            password_entry.iv_or_nonce = iv_or_nonce
            password_entry.salt = entry_salt
            password_entry.save()
        
        # 3. Lo mismo para archivos encriptados...
        
        # 4. Finalmente, actualizar la clave maestra
        master_key_entry.set_master_key(new_master_key)
        
        return JsonResponse({
            'success': True,
            'message': 'Clave maestra cambiada exitosamente'
        })
        """
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error cambiando clave maestra: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)