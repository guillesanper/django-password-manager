from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.views import View
from django.db import IntegrityError
from datetime import timedelta
from collections import Counter

import io
import os
import uuid
import json
import hashlib
import requests
import math
import re
import tempfile

from .models import PasswordEntry, MasterKey, EncryptedFile, UserSettings,ActivityLog,Vault
from .forms import UserRegisterForm, PasswordForm, EncryptedFileForm, PasswordUpdateForm, SettingsForm
from .encryption_utils import encrypt_password, decrypt_password, generate_passwords, encrypt_file, decrypt_file, encrypt_file_simple, decrypt_file_simple
from .utils.logging_utils import log_activity

# ==========================================
# VISTA PRINCIPAL PARA REACT SPA
# ==========================================

def app_view(request, path=''):
    """
    Vista principal para la SPA que maneja todas las rutas del frontend.
    Acepta un parámetro path opcional para el catch-all.
    """
    # Si es una petición para métricas, devolver métricas de Prometheus
    if path == 'metrics' or request.path == '/metrics':
        return metrics_view(request)
    
    # Para cualquier otra ruta, servir la SPA
    return render(request, 'index.html')


# ==========================================
# APIs JSON PARA REACT
# ==========================================

@login_required
def api_accounts(request):
    """API para obtener cuentas del usuario"""
    accounts = PasswordEntry.objects.filter(user=request.user)
    data = [{
        'id': acc.id,
        'website': acc.website,
        'username': acc.username,
        'encryption_algorithm': acc.encryption_algorithm,
        'encrypted_password': acc.encrypted_password,
        'salt': acc.salt,
        'iv_or_nonce': acc.iv_or_nonce,
        'encrypted_key': acc.encrypted_key
    } for acc in accounts]
    return JsonResponse({'accounts': data})


@login_required
def api_user_settings(request):
    """API para configuraciones del usuario"""
    settings_obj, created = UserSettings.objects.get_or_create(user=request.user)
    data = {
        'theme': settings_obj.theme,
        'require_password_modify': settings_obj.require_password_modify,
        'require_password_delete': settings_obj.require_password_delete,
        'notifications': settings_obj.notifications
    }
    return JsonResponse(data)


@login_required
def api_password_generator(request):
    """API para generar contraseñas"""
    # Parámetros por defecto o desde query params
    count = int(request.GET.get('count', 5))
    length = int(request.GET.get('length', 20))
    use_special = request.GET.get('special', 'true').lower() == 'true'
    use_numbers = request.GET.get('numbers', 'true').lower() == 'true'
    
    passwords = generate_passwords(count, length, use_special, use_numbers)
    return JsonResponse({'passwords': passwords})


@login_required
def api_unlock_password(request, password_id):
    """API para desbloquear una contraseña específica"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password')
        
        if not master_password:
            return JsonResponse({'error': 'Master password requerida'}, status=400)
        
        master_key_entry = get_object_or_404(MasterKey, user=request.user)
        if not master_key_entry.verify_master_key(master_password):
            return JsonResponse({'error': 'Master password incorrecta'}, status=400)
        
        account = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
        
        decrypted_password = decrypt_password(
            encrypted_password=account.encrypted_password,
            encrypted_key=account.encrypted_key, 
            iv_or_nonce=account.iv_or_nonce,
            master_key=master_key_entry.hashed_key.encode(),
            entry_salt=account.salt,
            algorithm=account.encryption_algorithm
        )
        
        return JsonResponse({
            'success': True,
            'password': decrypted_password.decode('utf-8'),
            'account': {
                'id': account.id,
                'website': account.website,
                'username': account.username
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_unlock_all_accounts(request):
    """API para desbloquear todas las cuentas"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password')
        
        if not master_password:
            return JsonResponse({'error': 'Master password requerida'}, status=400)
        
        master_key_entry = get_object_or_404(MasterKey, user=request.user)
        if not master_key_entry.verify_master_key(master_password):
            return JsonResponse({'error': 'Master password incorrecta'}, status=400)
        
        accounts = PasswordEntry.objects.filter(user=request.user)
        decrypted_accounts = []
        
        for account in accounts:
            try:
                decrypted_password = decrypt_password(
                    account.encrypted_password, 
                    account.encrypted_key, 
                    account.iv_or_nonce, 
                    master_key_entry.hashed_key.encode(), 
                    account.encryption_algorithm
                )
                decrypted_accounts.append({
                    'id': account.id,
                    'website': account.website,
                    'username': account.username,
                    'password': decrypted_password.decode('utf-8'),
                    'encryption_algorithm': account.encryption_algorithm
                })
            except Exception as e:
                # Si hay error desencriptando una cuenta, la omitimos
                continue
        
        return JsonResponse({
            'success': True,
            'accounts': decrypted_accounts
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ==========================================
# VISTAS POST - MANTENER COMO ESTÁN
# ==========================================

@login_required
@require_http_methods(["POST"])
@csrf_protect
def add_password(request):
    """Crear nueva entrada de contraseña - Solo API JSON"""
    try:
        data = json.loads(request.body)
        website = data.get('website', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        algorithm = data.get('algorithm', 'AES')
        
        # Validaciones básicas
        if not website:
            return JsonResponse({
                'success': False,
                'error': 'El sitio web es requerido'
            }, status=400)
        
        if not username:
            return JsonResponse({
                'success': False,
                'error': 'El nombre de usuario es requerido'
            }, status=400)
        
        if not password:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña es requerida'
            }, status=400)
        
        if len(password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña debe tener al menos 8 caracteres'
            }, status=400)
        
        if algorithm not in ['AES', 'ChaCha20']:
            return JsonResponse({
                'success': False,
                'error': 'Algoritmo de encriptación inválido'
            }, status=400)
        
        # Limpiar website URL (remover protocolo si existe)
        clean_website = website.replace('https://', '').replace('http://', '').replace('www.', '')
        
        # Obtener master key
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)

        # Encriptar contraseña
        encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
            password, master_key, algorithm
        )
        
        # Crear entrada
        password_entry = PasswordEntry.objects.create(
            user=request.user,
            website=clean_website,
            username=username,
            encrypted_password=encrypted_password,
            encryption_algorithm=algorithm,
            iv_or_nonce=iv_or_nonce,
            encrypted_key=encrypted_key,
            salt=entry_salt
        )
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='password_created',
            title='Nueva contraseña creada',
            description=f'Contraseña creada para {clean_website}',
            severity='success',
            related_obj=password_entry
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Contraseña creada exitosamente',
            'password_id': password_entry.id
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error creating password: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def delete_password(request, password_id):
    """Eliminar entrada de contraseña - Solo API JSON"""
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password', '').strip()
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener y eliminar contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
            website_name = password_entry.website
            
            password_entry.delete()
            
            # Log de actividad
            log_activity(
                user=request.user,
                activity_type='password_deleted',
                title='Contraseña eliminada',
                description=f'Contraseña de {website_name} eliminada',
                severity='warning'
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Contraseña eliminada exitosamente'
            })
            
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error deleting password: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def update_password(request, pk):
    """Actualizar entrada de contraseña - Solo API JSON"""
    try:
        data = json.loads(request.body)
        website = data.get('website', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')  # Puede ser vacío si no quieren cambiarla
        algorithm = data.get('algorithm', 'AES')
        master_password = data.get('master_password', '').strip()
        
        # Validaciones básicas
        if not website:
            return JsonResponse({
                'success': False,
                'error': 'El sitio web es requerido'
            }, status=400)
        
        if not username:
            return JsonResponse({
                'success': False,
                'error': 'El nombre de usuario es requerido'
            }, status=400)
        
        if algorithm not in ['AES', 'ChaCha20']:
            return JsonResponse({
                'success': False,
                'error': 'Algoritmo de encriptación inválido'
            }, status=400)
        
        # Si van a cambiar la contraseña, validar que esté presente y sea válida
        if password and len(password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña debe tener al menos 8 caracteres'
            }, status=400)
        
        # Si van a cambiar contraseña, necesitamos master password
        if password and not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida para cambiar contraseña'
            }, status=400)
        
        # Obtener entrada de contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=pk, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
        
        # Si van a cambiar contraseña, verificar master password
        if password and master_password:
            try:
                master_key_entry = MasterKey.objects.get(user=request.user)
                if not master_key_entry.verify_master_key(master_password):
                    return JsonResponse({
                        'success': False,
                        'error': 'Master password incorrecta'
                    }, status=400)
                
                # Re-encriptar con nueva contraseña
                master_key = master_key_entry.hashed_key.encode()
                encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
                    password, master_key, algorithm
                )
                
                password_entry.encrypted_password = encrypted_password
                password_entry.encrypted_key = encrypted_key
                password_entry.iv_or_nonce = iv_or_nonce
                password_entry.salt = entry_salt
                password_entry.encryption_algorithm = algorithm
                
            except MasterKey.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'No se encontró la clave maestra'
                }, status=400)
        
        # Limpiar website URL
        clean_website = website.replace('https://', '').replace('http://', '').replace('www.', '')
        
        # Actualizar campos básicos
        password_entry.website = clean_website
        password_entry.username = username
        
        # Solo actualizar algoritmo si no se cambió la contraseña
        if not password:
            password_entry.encryption_algorithm = algorithm
        
        password_entry.save()
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='password_updated',
            title='Contraseña actualizada',
            description=f'Contraseña de {clean_website} actualizada',
            severity='success'
        )

        return JsonResponse({
            'success': True,
            'message': 'Contraseña actualizada exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error updating password: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


# ==========================================
# AUTENTICACIÓN - MANTENER COMO ESTÁ
# ==========================================

class LoginView(View):
    @method_decorator(csrf_protect)
    def post(self, request):
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')

            if not email or not password:
                return JsonResponse({
                    'success': False,
                    'error': 'Email y contraseña son requeridos'
                }, status=400)

            # Autenticar usando el email (usando el backend personalizado)
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                if user.is_active:
                    login(request, user)
                    
                    # Crear configuraciones por defecto si no existen
                    user_settings, created = UserSettings.objects.get_or_create(
                        user=user,
                        defaults={
                            'theme': 'light',
                            'require_password_modify': True,
                            'require_password_delete': True,
                            'notifications': 'enabled'
                        }
                    )
                    
                    return JsonResponse({
                        'success': True,
                        'user': {
                            'id': user.id,
                            'username': user.username,
                            'email': user.email,
                            'firstName': user.first_name,
                            'lastName': user.last_name,
                            'isAuthenticated': True
                        }
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': 'La cuenta está desactivada'
                    }, status=400)
            else:
                return JsonResponse({
                    'success': False,
                    'error': 'Email o contraseña incorrectos'
                }, status=400)

        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Datos JSON inválidos'
            }, status=400)
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': 'Error interno del servidor'
            }, status=500)

class RegisterView(View):
    @method_decorator(csrf_protect)
    def post(self, request):
        try:
            data = json.loads(request.body)
            first_name = data.get('first_name', '').strip()
            last_name = data.get('last_name', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')

            # Validaciones básicas
            if not email or not password:
                return JsonResponse({
                    'success': False,
                    'error': 'Email y contraseña son requeridos'
                }, status=400)

            if len(password) < 8:
                return JsonResponse({
                    'success': False,
                    'error': 'La contraseña debe tener al menos 8 caracteres'
                }, status=400)

            # Verificar si el email ya existe
            if User.objects.filter(email=email).exists():
                return JsonResponse({
                    'success': False,
                    'error': 'Ya existe una cuenta con este email'
                }, status=400)

            # Generar username único basado en el email
            username = email.split('@')[0]
            original_username = username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{original_username}{counter}"
                counter += 1

            try:
                # Crear el usuario
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )

                # CAMBIO CRÍTICO: Autenticar correctamente antes de hacer login
                # Usar el mismo método que en LoginView con email como parámetro
                authenticated_user = authenticate(request, email=email, password=password)
                
                if authenticated_user is not None:
                    # Ahora hacer login con el usuario autenticado
                    login(request, authenticated_user)
                    
                    # Crear configuraciones por defecto
                    UserSettings.objects.create(
                        user=authenticated_user,
                        theme='light',
                        require_password_modify=True,
                        require_password_delete=True,
                        notifications='enabled'
                    )

                    return JsonResponse({
                        'success': True,
                        'user': {
                            'id': authenticated_user.id,
                            'username': authenticated_user.username,
                            'email': authenticated_user.email,
                            'firstName': authenticated_user.first_name,
                            'lastName': authenticated_user.last_name,
                            'isAuthenticated': True
                        }
                    })
                else:
                    # Si no se puede autenticar, intentar con username en lugar de email
                    # (fallback por si el backend personalizado no está funcionando)
                    authenticated_user = authenticate(request, username=user.username, password=password)
                    
                    if authenticated_user is not None:
                        login(request, authenticated_user)
                        
                        # Crear configuraciones por defecto
                        UserSettings.objects.create(
                            user=authenticated_user,
                            theme='light',
                            require_password_modify=True,
                            require_password_delete=True,
                            notifications='enabled'
                        )

                        return JsonResponse({
                            'success': True,
                            'user': {
                                'id': authenticated_user.id,
                                'username': authenticated_user.username,
                                'email': authenticated_user.email,
                                'firstName': authenticated_user.first_name,
                                'lastName': authenticated_user.last_name,
                                'isAuthenticated': True
                            }
                        })
                    else:
                        return JsonResponse({
                            'success': False,
                            'error': 'Error en la autenticación automática. Intenta iniciar sesión manualmente.'
                        }, status=400)

            except IntegrityError:
                return JsonResponse({
                    'success': False,
                    'error': 'Error al crear la cuenta. Inténtalo de nuevo.'
                }, status=400)

        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Datos JSON inválidos'
            }, status=400)
        except Exception as e:
            print(f"Error en registro: {str(e)}")  # Para debugging
            return JsonResponse({
                'success': False,
                'error': 'Error interno del servidor'
            }, status=500)

class LogoutView(View):
    @method_decorator(csrf_protect)
    def post(self, request):
        try:
            logout(request)
            return JsonResponse({
                'success': True,
                'message': 'Sesión cerrada exitosamente'
            })
        except Exception as e:
            return JsonResponse({
                'success': False,
                'error': 'Error al cerrar sesión'
            }, status=500)

@require_http_methods(["GET"])
def check_auth_status(request):
    """Endpoint para verificar el estado de autenticación"""
    if request.user.is_authenticated:
        return JsonResponse({
            'isAuthenticated': True,
            'user': {
                'id': request.user.id,
                'username': request.user.username,
                'email': request.user.email,
                'firstName': request.user.first_name,
                'lastName': request.user.last_name
            }
        })
    else:
        return JsonResponse({
            'isAuthenticated': False,
            'user': None
        })


@login_required(login_url='login')
def settings_view(request):
    """Vista de configuraciones"""
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
# VISTAS PARA MANEJO DE CLAVE MAESTRA
# ==========================================

@login_required
@require_http_methods(["POST"])
@csrf_protect
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


@login_required
@require_http_methods(["GET"])
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


@login_required
@require_http_methods(["POST"])
@csrf_protect
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


@login_required
@require_http_methods(["POST"])
@csrf_protect
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
        
# ===============================================
# VISTAS PARA MANEJO DE ESTADISTICAS DE DASHBOARD
# ===============================================
@login_required
def api_dashboard_stats(request):
    """API para estadísticas del dashboard incluyendo información de vaults"""
    try:
        # Estadísticas básicas existentes
        passwords_count = PasswordEntry.objects.filter(user=request.user).count()
        files_count = EncryptedFile.objects.filter(user=request.user).count()
        active_sessions = 1  # Hardcoded por ahora
        
        # Estadísticas de vaults
        vault_summary = get_vault_summary(request.user)
        
        # Score de seguridad
        strong_passwords = PasswordEntry.objects.filter(
            user=request.user, 
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        security_score = min(95, (strong_passwords / max(passwords_count, 1)) * 100)
        
        response_data = {
            'passwords_count': passwords_count,
            'files_count': files_count,
            'active_sessions': active_sessions,
            'security_score': round(security_score),
            'vault_summary': vault_summary
        }
        
        return JsonResponse(response_data)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required 
def api_recent_activity(request):
    """API para actividad reciente"""
    try:
        activities = []
        
        # Obtener actividades del log si existe
        recent_logs = ActivityLog.objects.filter(user=request.user)[:4]
        
        if recent_logs.exists():
            for log in recent_logs:
                activities.append({
                    'type': log.activity_type,
                    'title': log.title,
                    'description': log.description,
                    'time': log.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': log.severity
                })
        else:
            # Si no hay logs, generar datos basados en contraseñas y archivos recientes
            # Últimas contraseñas creadas
            recent_passwords = PasswordEntry.objects.filter(user=request.user).order_by('-created_at')[:2]
            for pwd in recent_passwords:
                activities.append({
                    'type': 'password_created',
                    'title': 'Nueva contraseña generada',
                    'description': f'Contraseña segura generada para {pwd.website}',
                    'time': pwd.created_at.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': 'success'
                })
            
            # Últimos archivos
            recent_files = EncryptedFile.objects.filter(user=request.user).order_by('-uploaded_at')[:2]
            for file in recent_files:
                activities.append({
                    'type': 'file_encrypted',
                    'title': 'Archivo encriptado',
                    'description': f'{file.title} fue encriptado',
                    'time': file.uploaded_at.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': 'info'
                })
        
        return JsonResponse({'activities': activities[:4]})  # Últimas 4
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_security_summary(request):
    """API para resumen de seguridad"""
    try:
        passwords = PasswordEntry.objects.filter(user=request.user)
        total_passwords = passwords.count()
        
        # Contraseñas seguras (usando algoritmos fuertes)
        strong_passwords = passwords.filter(
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        
        # Contraseñas que necesitan actualización (más de 90 días)
        from django.utils import timezone
        from datetime import timedelta
        
        needs_update = passwords.filter(
            updated_at__lt=timezone.now() - timedelta(days=365)
        ).count()
        
        # Contraseñas antiguas (más de 180 días)
        old_passwords = passwords.filter(
            created_at__lt=timezone.now() - timedelta(days=720)
        ).count()
        
        return JsonResponse({
            'strong_passwords': strong_passwords,
            'needs_update': needs_update,
            'old_passwords': old_passwords,
            'total_passwords': total_passwords
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

# ==========================================
# FUNCIONES DE ANÁLISIS DE SEGURIDAD
# ==========================================

def calculate_password_entropy(password: str) -> float:
    """
    Calcula la entropía de una contraseña en bits
    """
    if not password:
        return 0.0
    
    # Definir los sets de caracteres
    lowercase = set('abcdefghijklmnopqrstuvwxyz')
    uppercase = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    digits = set('0123456789')
    special = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
    
    # Determinar qué sets de caracteres se usan
    charset_size = 0
    password_set = set(password)
    
    if password_set.intersection(lowercase):
        charset_size += 26
    if password_set.intersection(uppercase):
        charset_size += 26
    if password_set.intersection(digits):
        charset_size += 10
    if password_set.intersection(special):
        charset_size += len(special)
    
    # Si hay caracteres que no están en los sets conocidos, agregarlos
    known_chars = lowercase | uppercase | digits | special
    unknown_chars = password_set - known_chars
    charset_size += len(unknown_chars)
    
    # Calcular entropía básica
    if charset_size == 0:
        return 0.0
    
    entropy = len(password) * math.log2(charset_size)
    
    # Reducir entropía por patrones comunes
    # Secuencias (abc, 123)
    sequence_penalty = 0
    for i in range(len(password) - 2):
        substring = password[i:i+3]
        if (substring.lower() in 'abcdefghijklmnopqrstuvwxyz' or 
            substring in '0123456789' or
            substring in '9876543210'):
            sequence_penalty += 2
    
    # Repeticiones
    char_counts = Counter(password)
    repetition_penalty = sum(count - 1 for count in char_counts.values() if count > 1)
    
    # Patrones de teclado (qwerty, asdf)
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', '4567']
    keyboard_penalty = 0
    password_lower = password.lower()
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            keyboard_penalty += len(pattern)
    
    # Aplicar penalizaciones
    total_penalty = sequence_penalty + repetition_penalty + keyboard_penalty
    entropy = max(0, entropy - total_penalty)
    
    return entropy

def get_password_strength_category(entropy: float) -> dict:
    """
    Categoriza la fortaleza de la contraseña basada en la entropía
    """
    if entropy >= 70:
        return {
            'level': 'very_strong',
            'label': 'Muy Fuerte',
            'color': '#10b981',
            'score': 100
        }
    elif entropy >= 50:
        return {
            'level': 'strong',
            'label': 'Fuerte',
            'color': '#3b82f6',
            'score': 80
        }
    elif entropy >= 35:
        return {
            'level': 'moderate',
            'label': 'Moderada',
            'color': '#f59e0b',
            'score': 60
        }
    elif entropy >= 25:
        return {
            'level': 'weak',
            'label': 'Débil',
            'color': '#f97316',
            'score': 40
        }
    else:
        return {
            'level': 'very_weak',
            'label': 'Muy Débil',
            'color': '#ef4444',
            'score': 20
        }

def check_password_breach_sync(password: str) -> dict:
    """
    Verifica si una contraseña aparece en HaveIBeenPwned usando k-anonymity
    """
    try:
        # Crear SHA-1 hash de la contraseña
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Hacer petición a HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # Buscar nuestro hash en la respuesta
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return {
                        'is_breached': True,
                        'breach_count': int(count),
                        'message': f'Esta contraseña aparece {count} veces en filtraciones de datos conocidas'
                    }
            
            return {
                'is_breached': False,
                'breach_count': 0,
                'message': 'No se encontró en filtraciones conocidas'
            }
        else:
            return {
                'is_breached': False,
                'breach_count': 0,
                'message': 'No se pudo verificar (error del servicio)',
                'error': True
            }
            
    except Exception as e:
        return {
            'is_breached': False,
            'breach_count': 0,
            'message': 'No se pudo verificar (error de conexión)',
            'error': True
        }

def find_duplicate_passwords(passwords: list) -> list:
    """
    Encuentra contraseñas duplicadas
    """
    password_groups = {}
    for pwd_data in passwords:
        pwd = pwd_data['password']
        if pwd in password_groups:
            password_groups[pwd].append(pwd_data)
        else:
            password_groups[pwd] = [pwd_data]
    
    # Retornar solo los grupos con duplicados
    return {k: v for k, v in password_groups.items() if len(v) > 1}

def analyze_password_patterns(passwords: list) -> dict:
    """
    Analiza patrones comunes en las contraseñas
    """
    patterns = {
        'common_prefixes': Counter(),
        'common_suffixes': Counter(),
        'length_distribution': Counter(),
        'character_usage': {
            'uppercase': 0,
            'lowercase': 0,
            'digits': 0,
            'special': 0
        }
    }
    
    for pwd_data in passwords:
        pwd = pwd_data['password']
        
        # Longitud
        patterns['length_distribution'][len(pwd)] += 1
        
        # Prefijos y sufijos comunes (primeros/últimos 3 caracteres)
        if len(pwd) >= 3:
            patterns['common_prefixes'][pwd[:3].lower()] += 1
            patterns['common_suffixes'][pwd[-3:].lower()] += 1
        
        # Uso de caracteres
        if re.search(r'[A-Z]', pwd):
            patterns['character_usage']['uppercase'] += 1
        if re.search(r'[a-z]', pwd):
            patterns['character_usage']['lowercase'] += 1
        if re.search(r'\d', pwd):
            patterns['character_usage']['digits'] += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', pwd):
            patterns['character_usage']['special'] += 1
    
    return patterns

# ==========================================
# VISTAS DE LA API DE SEGURIDAD
# ==========================================

@login_required
@require_http_methods(["GET"])
def api_security_analysis(request):
    """
    Análisis completo de seguridad de todas las contraseñas del usuario
    """
    try:
        # Obtener todas las contraseñas del usuario
        password_entries = PasswordEntry.objects.filter(user=request.user)
        
        if not password_entries.exists():
            return JsonResponse({
                'success': True,
                'total_passwords': 0,
                'analysis': {
                    'overall_score': 100,
                    'strength_distribution': {},
                    'security_issues': [],
                    'recommendations': ['Agrega algunas contraseñas para comenzar el análisis de seguridad']
                }
            })
        
        # Obtener master key para desencriptar
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Desencriptar y analizar cada contraseña
        password_analyses = []
        decrypted_passwords = []
        
        for entry in password_entries:
            try:
                decrypted_password = decrypt_password(
                    entry.encrypted_password,
                    entry.encrypted_key,
                    entry.iv_or_nonce,
                    master_key_entry.hashed_key.encode(),
                    entry.salt,
                    entry.encryption_algorithm
                ).decode('utf-8')
                
                # Calcular entropía
                entropy = calculate_password_entropy(decrypted_password)
                strength = get_password_strength_category(entropy)
                
                # Verificar en HaveIBeenPwned (esto es síncrono por simplicidad)
                breach_info = check_password_breach_sync(decrypted_password)
                
                analysis = {
                    'id': entry.id,
                    'website': entry.website,
                    'username': entry.username,
                    'entropy': round(entropy, 2),
                    'strength': strength,
                    'breach_info': breach_info,
                    'age_days': (timezone.now() - entry.created_at).days,
                    'last_updated_days': (timezone.now() - entry.updated_at).days
                }
                
                password_analyses.append(analysis)
                decrypted_passwords.append({
                    'password': decrypted_password,
                    'website': entry.website,
                    'id': entry.id
                })
                
            except Exception as e:
                # Si no se puede desencriptar una contraseña, la omitimos
                continue
        
        # Análisis agregado
        if not password_analyses:
            return JsonResponse({
                'success': False,
                'error': 'No se pudieron analizar las contraseñas'
            }, status=500)
        
        # Distribución de fortaleza
        strength_distribution = Counter()
        total_entropy = 0
        breached_count = 0
        old_passwords = 0
        weak_passwords = 0
        
        for analysis in password_analyses:
            strength_distribution[analysis['strength']['level']] += 1
            total_entropy += analysis['entropy']
            
            if analysis['breach_info']['is_breached']:
                breached_count += 1
            
            if analysis['age_days'] > 365:  # Más de 1 año
                old_passwords += 1
                
            if analysis['strength']['level'] in ['weak', 'very_weak']:
                weak_passwords += 1
        
        # Encontrar duplicados
        duplicates = find_duplicate_passwords(decrypted_passwords)
        
        # Patrones
        patterns = analyze_password_patterns(decrypted_passwords)
        
        # Calcular score general
        total_passwords = len(password_analyses)
        avg_entropy = total_entropy / total_passwords
        
        # Score basado en múltiples factores
        entropy_score = min(100, (avg_entropy / 60) * 40)  # 40% del score
        breach_score = ((total_passwords - breached_count) / total_passwords) * 30  # 30% del score
        age_score = ((total_passwords - old_passwords) / total_passwords) * 20  # 20% del score
        strength_score = ((total_passwords - weak_passwords) / total_passwords) * 10  # 10% del score
        
        overall_score = round(entropy_score + breach_score + age_score + strength_score)
        
        # Generar recomendaciones
        recommendations = []
        security_issues = []
        
        if weak_passwords > 0:
            security_issues.append({
                'type': 'weak_passwords',
                'count': weak_passwords,
                'severity': 'high',
                'message': f'{weak_passwords} contraseñas son débiles o muy débiles'
            })
            recommendations.append(f'Actualiza {weak_passwords} contraseñas débiles por otras más seguras')
        
        if breached_count > 0:
            security_issues.append({
                'type': 'breached_passwords',
                'count': breached_count,
                'severity': 'critical',
                'message': f'{breached_count} contraseñas encontradas en filtraciones de datos'
            })
            recommendations.append(f'Cambia inmediatamente {breached_count} contraseñas comprometidas')
        
        if len(duplicates) > 0:
            duplicate_count = sum(len(group) for group in duplicates.values())
            security_issues.append({
                'type': 'duplicate_passwords',
                'count': len(duplicates),
                'severity': 'medium',
                'message': f'{duplicate_count} contraseñas duplicadas encontradas'
            })
            recommendations.append('Usa contraseñas únicas para cada cuenta')
        
        if old_passwords > 0:
            security_issues.append({
                'type': 'old_passwords',
                'count': old_passwords,
                'severity': 'medium',
                'message': f'{old_passwords} contraseñas tienen más de 1 año'
            })
            recommendations.append('Actualiza contraseñas antiguas regularmente')
        
        if not recommendations:
            recommendations.append('¡Excelente! Tu seguridad de contraseñas está en buen estado')
        
        return JsonResponse({
            'success': True,
            'total_passwords': total_passwords,
            'analysis': {
                'overall_score': overall_score,
                'average_entropy': round(avg_entropy, 2),
                'strength_distribution': dict(strength_distribution),
                'security_issues': security_issues,
                'recommendations': recommendations,
                'patterns': {
                    'duplicate_groups': len(duplicates),
                    'length_distribution': dict(patterns['length_distribution']),
                    'character_usage_stats': patterns['character_usage']
                }
            },
            'passwords': password_analyses
        })
        
    except Exception as e:
        print(f"Error en análisis de seguridad: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno al analizar la seguridad'
        }, status=500)

@login_required
@require_http_methods(["POST"])
def api_check_single_password_breach(request):
    """
    Verificar una contraseña específica contra HaveIBeenPwned
    """
    try:
        data = json.loads(request.body)
        password_id = data.get('password_id')
        master_password = data.get('master_password')
        
        if not password_id or not master_password:
            return JsonResponse({
                'success': False,
                'error': 'ID de contraseña y master password requeridos'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener y desencriptar la contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
            decrypted_password = decrypt_password(
                password_entry.encrypted_password,
                password_entry.encrypted_key,
                password_entry.iv_or_nonce,
                master_key_entry.hashed_key.encode(),
                password_entry.salt,
                password_entry.encryption_algorithm
            ).decode('utf-8')
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
        
        # Verificar contra HaveIBeenPwned
        breach_info = check_password_breach_sync(decrypted_password)
        
        return JsonResponse({
            'success': True,
            'password_id': password_id,
            'breach_info': breach_info
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error verificando contraseña: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)

@login_required 
@require_http_methods(["GET"])
def api_security_recommendations(request):
    """
    Obtener recomendaciones personalizadas de seguridad
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
        
        # Verificar contraseñas débiles
        # (Esto requeriría desencriptar, pero para recomendaciones generales podemos usar heurísticas)
        
        # Contraseñas antiguas
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
        
        # Algoritmos de encriptación débiles
        weak_algorithms = password_entries.exclude(
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        
        if weak_algorithms > 0:
            recommendations.append({
                'type': 'upgrade_encryption',
                'priority': 'low',
                'title': 'Actualizar algoritmo de encriptación',
                'description': f'{weak_algorithms} contraseñas usan algoritmos de encriptación menos seguros',
                'action': 'reencrypt_passwords',
                'count': weak_algorithms
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
        
    except Exception as e:
        print(f"Error obteniendo recomendaciones: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error al obtener recomendaciones'
        }, status=500)
        
        
def metrics_view(request):
    """
    Vista para servir métricas de Prometheus.
    """
    try:
        # Aquí puedes generar métricas personalizadas
        from django.contrib.auth.models import User
        from django.db import connection
        
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
    except Exception as e:
        return HttpResponse(
            f"# Error generating metrics: {str(e)}\n",
            content_type='text/plain; version=0.0.4; charset=utf-8',
            status=500
        )
        
        
# ==========================================
# VISTAS DE ARCHIVOS CON MINIO - ACTUALIZACIÓN SEGURA
# ==========================================

@login_required
def api_files(request):
    """API para obtener archivos del usuario con información de MinIO"""
    try:
        files = EncryptedFile.objects.filter(user=request.user)
        
        # Obtener información adicional de MinIO si es necesario
        from .minio_service import enhanced_minio_service
        
        data = []
        for file in files:
            try:
                # Información básica de la base de datos
                file_info = {
                    'id': file.id,
                    'title': file.title,
                    'algorithm': file.algorithm,
                    'uploaded_at': file.uploaded_at.isoformat(),
                    'updated_at': file.updated_at.isoformat(),
                    'encrypted_key': file.encrypted_key,
                    'salt': file.salt,
                    'iv_or_nonce': file.iv_or_nonce,
                    'file_path': file.file_path
                }
                
                # Obtener información adicional de MinIO
                if file.file_path:
                    object_name = file.file_path
                    minio_info = enhanced_minio_service.get_file_info(
                        object_name=object_name,
                        user_id=request.user.id
                    )
                    
                    if minio_info['success']:
                        file_info.update({
                            'size': minio_info['info']['size'],
                            'size_formatted': format_file_size(minio_info['info']['size']),
                            'minio_last_modified': minio_info['info'].get('last_modified'),
                            'etag': minio_info['info'].get('etag'),
                            'encryption_metadata': minio_info['info'].get('metadata', {})
                        })
                
                data.append(file_info)
                
            except Exception as e:
                error_msg = str(e)
                file_data = {
                    'id': file.id,
                    'title': file.title,
                    'algorithm': file.algorithm,
                    'uploaded_at': file.uploaded_at.isoformat(),
                    'updated_at': file.updated_at.isoformat(),
                    'file_path': file.file_path
                }
                
                # Solo agregar error si es un error real (no solo falta de metadata)
                if 'NoSuchKey' in error_msg or 'not found' in error_msg.lower():
                    file_data['minio_error'] = 'Archivo no encontrado en almacenamiento'
                # Para otros errores menores, no mostrar advertencia
                
                data.append(file_data)
        
        return JsonResponse({'files': data})
        
    except Exception as e:
        return JsonResponse({
            'error': 'Error obteniendo lista de archivos',
            'details': str(e)
        }, status=500)


# ==========================================
# FUNCIONES AUXILIARES
# ==========================================

def format_file_size(size_bytes):
    """Formatear tamaño de archivo en formato legible"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_names[i]}"


# ==========================================
# API PARA ESTADÍSTICAS DE ARCHIVOS
# ==========================================

@login_required
def api_files_stats(request):
    """API para estadísticas de archivos del usuario"""
    try:
        user_files = EncryptedFile.objects.filter(user=request.user)
        
        if not user_files.exists():
            return JsonResponse({
                'success': True,
                'stats': {
                    'total_files': 0,
                    'total_size': 0,
                    'algorithms_used': [],
                    'recent_uploads': 0
                }
            })
        
        # Obtener información de MinIO para calcular tamaños
        from .minio_service import enhanced_minio_service
        
        total_size = 0
        algorithms = []
        successful_reads = 0
        
        for file in user_files:
            algorithms.append(file.algorithm)
            
            try:
                object_name = file.file_path
                minio_info = enhanced_minio_service.get_file_info(
                    object_name=object_name,
                    user_id=request.user.id
                )
                
                if minio_info['success']:
                    total_size += minio_info['info']['size']
                    successful_reads += 1
                    
            except Exception:
                # Ignorar errores individuales
                continue
        
        # Archivos recientes (últimos 7 días)
        recent_uploads = user_files.filter(
            uploaded_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total_files': user_files.count(),
                'total_size': total_size,
                'total_size_formatted': format_file_size(total_size),
                'algorithms_used': list(set(algorithms)),
                'recent_uploads': recent_uploads,
                'minio_sync_success': successful_reads,
                'algorithm_distribution': dict(Counter(algorithms))
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo estadísticas',
            'details': str(e)
        }, status=500)
        
# FUNCIÓN AUXILIAR PARA DEBUGGING
@login_required
@require_http_methods(["POST"])  
def debug_file_info(request, file_id):
    """Función auxiliar para debuggear información de archivos"""
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password', '').strip()
        
        # Obtener registro del archivo
        file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
        master_key_entry = MasterKey.objects.get(user=request.user)
        
        # Verificar master password si se proporciona
        master_key_valid = False
        if master_password:
            master_key_valid = master_key_entry.verify_master_key(master_password)
        
        # Información del archivo
        debug_info = {
            'file_id': file_id,
            'title': file_entry.title,
            'algorithm': file_entry.algorithm,
            'salt_length': len(file_entry.salt) if file_entry.salt else 0,
            'iv_or_nonce_length': len(file_entry.iv_or_nonce) if file_entry.iv_or_nonce else 0,
            'encrypted_key_length': len(file_entry.encrypted_key) if file_entry.encrypted_key else 0,
            'file_path': file_entry.file_path,
            'master_key_valid': master_key_valid,
            'master_key_type': type(master_key_entry.hashed_key).__name__,
            'master_key_length': len(master_key_entry.hashed_key) if master_key_entry.hashed_key else 0,
        }
        
        # Información de MinIO si es posible
        try:
            from .minio_service import enhanced_minio_service
            response = enhanced_minio_service.client.get_object(
                enhanced_minio_service.bucket_name, 
                file_entry.file_path
            )
            encrypted_data = response.read()
            response.close()
            
            debug_info.update({
                'minio_file_size': len(encrypted_data),
                'minio_accessible': True,
                'first_16_bytes_hex': encrypted_data[:16].hex() if len(encrypted_data) >= 16 else encrypted_data.hex()
            })
            
        except Exception as minio_error:
            debug_info.update({
                'minio_accessible': False,
                'minio_error': str(minio_error)
            })
        
        return JsonResponse({
            'success': True,
            'debug_info': debug_info
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })


# ==========================================
# FUNCIÓN AUXILIAR PARA MANEJO DE NOMBRES DE ARCHIVO - CORREGIDA
# ==========================================

import urllib.parse
import re
from django.http import HttpResponse

def sanitize_filename_for_download(filename):
    """
    Sanitiza y formatea correctamente el nombre del archivo para descarga
    """
    if not filename:
        return "archivo_descargado"
    
    # Limpiar caracteres problemáticos pero mantener la extensión
    # Remover caracteres peligrosos pero preservar espacios, puntos, guiones
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
    
    # Asegurar que no esté vacío después de sanitizar
    if not sanitized.strip():
        return "archivo_descargado"
    
    return sanitized.strip()

def create_download_response(file_data, filename, content_type='application/octet-stream'):
    """
    Crea una respuesta HTTP correcta para descarga de archivos - FILENAME CON COMILLAS
    """
    # Verificar que file_data es bytes
    if isinstance(file_data, str):
        file_data = file_data.encode('utf-8')
    
    # Crear respuesta con content_type correcto
    response = HttpResponse(file_data, content_type=content_type)
    
    # Sanitizar nombre
    safe_filename = sanitize_filename_for_download(filename)
    
    # CORRECCIÓN CRÍTICA: Siempre usar comillas para filenames
    try:
        # Intentar codificar como ASCII
        safe_filename.encode('ascii')
        # CAMBIO: SIEMPRE usar comillas, incluso para ASCII
        response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
        print(f"[DEBUG] Content-Disposition ASCII: attachment; filename=\"{safe_filename}\"")
    except UnicodeEncodeError:
        # Para caracteres no-ASCII, usar ambos métodos
        encoded_filename = urllib.parse.quote(safe_filename.encode('utf-8'))
        ascii_fallback = re.sub(r'[^\x20-\x7E]', '_', safe_filename)
        response['Content-Disposition'] = (
            f"attachment; "
            f"filename*=UTF-8''{encoded_filename}; "
            f'filename="{ascii_fallback}"'  # CAMBIO: Comillas aquí también
        )
        print(f"[DEBUG] Content-Disposition UTF-8: filename*=UTF-8''{encoded_filename}; filename=\"{ascii_fallback}\"")
    
    # Headers adicionales
    response['Content-Length'] = len(file_data)
    response['Content-Type'] = content_type
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    
    print(f"[DEBUG] Preparando descarga: {safe_filename}, {len(file_data)} bytes")
    print(f"[DEBUG] Content-Disposition final: {response['Content-Disposition']}")
    print(f"[DEBUG] Content-Type: {content_type}")
    
    return response



# ==========================================
# FUNCIÓN AUXILIAR MEJORADA PARA CONTENT-TYPE
# ==========================================

def get_content_type_from_filename(filename):
    """
    Obtiene el content-type basado en la extensión del archivo - MEJORADA
    """
    import mimetypes
    
    if not filename:
        return 'application/octet-stream'
    
    # Intentar primero con mimetypes
    content_type, encoding = mimetypes.guess_type(filename)
    
    if content_type:
        return content_type
    
    # Fallbacks para extensiones comunes
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    
    mime_types = {
        # Documentos
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'txt': 'text/plain; charset=utf-8',
        'rtf': 'application/rtf',
        
        # Hojas de cálculo
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'csv': 'text/csv; charset=utf-8',
        
        # Presentaciones
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        
        # Imágenes
        'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'svg': 'image/svg+xml',
        'webp': 'image/webp',
        'bmp': 'image/bmp',
        'tiff': 'image/tiff', 'tif': 'image/tiff',
        
        # Audio
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'm4a': 'audio/mp4',
        'ogg': 'audio/ogg',
        'flac': 'audio/flac',
        
        # Video
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime',
        'webm': 'video/webm',
        'mkv': 'video/x-matroska',
        
        # Archivos comprimidos
        'zip': 'application/zip',
        'rar': 'application/x-rar-compressed',
        '7z': 'application/x-7z-compressed',
        'tar': 'application/x-tar',
        'gz': 'application/gzip',
        
        # Código y texto
        'js': 'application/javascript',
        'json': 'application/json',
        'xml': 'application/xml',
        'html': 'text/html; charset=utf-8',
        'css': 'text/css; charset=utf-8',
        'py': 'text/x-python; charset=utf-8',
        'java': 'text/x-java; charset=utf-8',
        'cpp': 'text/x-c++; charset=utf-8',
        'c': 'text/x-c; charset=utf-8'
    }
    
    return mime_types.get(extension, 'application/octet-stream')


# ==========================================
# FUNCIÓN DE DEBUG PARA VERIFICAR DATOS
# ==========================================

def debug_file_data(data, filename="unknown"):
    """
    Función auxiliar para debuggear los datos del archivo
    """
    print(f"[DEBUG] Análisis de archivo: {filename}")
    print(f"  - Tipo: {type(data)}")
    print(f"  - Tamaño: {len(data)} bytes")
    
    if isinstance(data, bytes):
        # Mostrar primeros 50 bytes como hex
        hex_preview = data[:50].hex() if len(data) >= 50 else data.hex()
        print(f"  - Hex preview: {hex_preview}...")
        
        # Verificar si parece ser texto UTF-8
        try:
            text_preview = data[:100].decode('utf-8', errors='ignore')
            print(f"  - Text preview: {text_preview[:50]}...")
        except:
            print("  - No es texto UTF-8")
            
        # Verificar headers de archivos comunes
        if data.startswith(b'%PDF'):
            print("  - Detectado: PDF")
        elif data.startswith(b'PK'):
            print("  - Detectado: ZIP/Office Document")
        elif data.startswith(b'\xff\xd8\xff'):
            print("  - Detectado: JPEG")
        elif data.startswith(b'\x89PNG'):
            print("  - Detectado: PNG")
    else:
        print(f"  - Contenido: {str(data)[:100]}...")
        

# ==========================================
# FUNCIONES COMBINADAS MEJORADAS - DOBLE ENCRIPTACIÓN + MANEJO ROBUSTO
# ==========================================

@login_required
@require_http_methods(["POST"])
@csrf_protect
def upload_file_combined(request):
    """
    Subir archivo con doble encriptación (encryption_utils + Fernet) 
    usando manejo robusto de respuestas
    """
    try:
        # Verificar que se envió un archivo
        if 'file' not in request.FILES:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró ningún archivo'
            }, status=400)
        
        uploaded_file = request.FILES['file']
        algorithm = request.POST.get('algorithm', 'AES')
        master_password = request.POST.get('master_password', '').strip()
        
        # Validaciones básicas
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        if algorithm not in ['AES', 'ChaCha20']:
            return JsonResponse({
                'success': False,
                'error': 'Algoritmo de encriptación inválido'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Validar tamaño del archivo (máximo 100MB)
        max_size = 100 * 1024 * 1024  # 100MB
        if uploaded_file.size > max_size:
            return JsonResponse({
                'success': False,
                'error': 'El archivo es demasiado grande (máximo 100MB)'
            }, status=400)
        
        # PASO 1: Leer archivo completo en memoria
        file_data = uploaded_file.read()
        print(f"[DEBUG] Archivo original: {len(file_data)} bytes")
        
        # PASO 2: Primera capa - Encriptar con encryption_utils
        master_key = master_key_entry.hashed_key.encode() if isinstance(master_key_entry.hashed_key, str) else master_key_entry.hashed_key
        
        from .encryption_utils import encrypt_file_data
        
        first_layer_encrypted, encrypted_file_key, iv_or_nonce, entry_salt = encrypt_file_data(
            file_data=file_data,
            master_key=master_key,
            algorithm=algorithm
        )
        
        print(f"[DEBUG] Primera capa encriptada: {len(first_layer_encrypted)} bytes")
        
        # PASO 3: Segunda capa - Encriptar con Fernet (sistema)
        from .minio_service import enhanced_minio_service
        final_encrypted_data = enhanced_minio_service.system_fernet.encrypt(first_layer_encrypted)
        
        print(f"[DEBUG] Segunda capa encriptada: {len(final_encrypted_data)} bytes")
        
        # PASO 4: Preparar para subida a MinIO
        unique_filename = f"{uuid.uuid4()}_{uploaded_file.name}"
        object_name = f"user_{request.user.id}/{unique_filename}"
        
        # Metadatos del archivo
        metadata = {
            'user_id': str(request.user.id),
            'encryption_algorithm': algorithm,
            'double_encrypted': 'True',
            'user_salt': entry_salt,
            'upload_timestamp': timezone.now().isoformat(),
            'original_filename': uploaded_file.name,
            'file_size': str(uploaded_file.size),
            'iv_or_nonce': iv_or_nonce
        }
        
        # PASO 5: Subir a MinIO
        file_stream = io.BytesIO(final_encrypted_data)
        
        result = enhanced_minio_service.client.put_object(
            enhanced_minio_service.bucket_name,
            object_name,
            file_stream,
            len(final_encrypted_data),
            content_type='application/octet-stream',
            metadata=metadata
        )
        
        print(f"[DEBUG] Subido a MinIO: {object_name}")
        
        # PASO 6: Crear registro en la base de datos
        file_entry = EncryptedFile.objects.create(
            user=request.user,
            title=uploaded_file.name,  # Usar nombre sanitizado
            algorithm=algorithm,
            salt=entry_salt,
            iv_or_nonce=iv_or_nonce,
            encrypted_key=encrypted_file_key,
            file_path=object_name
        )
        
        # PASO 7: Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_uploaded',
            title='Archivo encriptado subido (Doble Encriptación)',
            description=f'Archivo {uploaded_file.name} encriptado con {algorithm} + Fernet',
            severity='success',
            related_obj=file_entry
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Archivo subido exitosamente con doble encriptación',
            'file': {
                'id': file_entry.id,
                'title': file_entry.title,
                'algorithm': f'{file_entry.algorithm} + Fernet',
                'uploaded_at': file_entry.uploaded_at.isoformat(),
                'size': uploaded_file.size,
                'encryption_layers': 2
            }
        })
        
    except Exception as e:
        print(f"[ERROR] Error en upload_file_combined: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def download_file_combined(request, file_id):
    """
    Descargar archivo con doble desencriptación (Fernet + encryption_utils)
    usando manejo robusto de respuestas
    """
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password', '').strip()
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener registro del archivo
        try:
            file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
        except EncryptedFile.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Archivo no encontrado'
            }, status=404)
        
        # PASO 1: Descargar de MinIO
        from .minio_service import enhanced_minio_service
        
        try:
            # Usar método que descarga y desencripta segunda capa automáticamente
            download_result = enhanced_minio_service.download_file(file_entry.file_path)
            
            if not download_result['success']:
                return JsonResponse({
                    'success': False,
                    'error': download_result['error']
                }, status=500)
            
            first_layer_encrypted = download_result['data']
            print(f"[DEBUG] Descargado y primera desencriptación: {len(first_layer_encrypted)} bytes")
            
        except Exception as e:
            print(f"[ERROR] Error descargando de MinIO: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Error descargando archivo: {str(e)}'
            }, status=500)
        
        # PASO 2: Segunda desencriptación con encryption_utils
        try:
            master_key = master_key_entry.hashed_key.encode() if isinstance(master_key_entry.hashed_key, str) else master_key_entry.hashed_key
            
            print(f"[DEBUG] Desencriptando segunda capa con:")
            print(f"  - Algorithm: {file_entry.algorithm}")
            print(f"  - Salt length: {len(file_entry.salt)}")
            print(f"  - IV/Nonce length: {len(file_entry.iv_or_nonce)}")
            print(f"  - Encrypted key length: {len(file_entry.encrypted_key)}")
            
            from .encryption_utils import decrypt_file_data
            
            decrypted_data = decrypt_file_data(
                encrypted_data=first_layer_encrypted,
                master_key=master_key,
                encrypted_file_key=file_entry.encrypted_key,
                iv_or_nonce=file_entry.iv_or_nonce,
                entry_salt=file_entry.salt,
                algorithm=file_entry.algorithm
            )
            
            print(f"[DEBUG] Archivo completamente desencriptado: {len(decrypted_data)} bytes")
            
            # Verificar que los datos son bytes
            if not isinstance(decrypted_data, bytes):
                print(f"[WARNING] Datos no son bytes, convirtiendo...")
                if isinstance(decrypted_data, str):
                    decrypted_data = decrypted_data.encode('utf-8')
                else:
                    decrypted_data = bytes(decrypted_data)
            
        except Exception as decrypt_error:
            print(f"[ERROR] Error en desencriptación: {decrypt_error}")
            import traceback
            traceback.print_exc()
            return JsonResponse({
                'success': False,
                'error': f'Error desencriptando archivo: {str(decrypt_error)}'
            }, status=500)
        
        # PASO 3: Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_downloaded',
            title='Archivo descargado (Doble Desencriptación)',
            description=f'Archivo {file_entry.title} descargado y desencriptado completamente',
            severity='info'
        )
        
        # PASO 4: Determinar content-type y crear respuesta
        content_type = get_content_type_from_filename(file_entry.title)
        
        return create_download_response(
            file_data=decrypted_data,
            filename=file_entry.title,
            content_type=content_type
        )
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"[ERROR] Error general en download_file_combined: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def delete_file_combined(request, file_id):
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password', '').strip()
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener registro del archivo
        try:
            file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
        except EncryptedFile.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Archivo no encontrado'
            }, status=404)
        
        # DEBUG: Verificar datos antes de eliminar
        print(f"[DEBUG] Eliminando archivo:")
        print(f"  - ID: {file_entry.id}")
        print(f"  - Title: {file_entry.title}")
        print(f"  - File path: '{file_entry.file_path}'")
        print(f"  - User ID: {request.user.id}")
        
        # Verificar que file_path no esté vacío
        if not file_entry.file_path:
            print(f"[ERROR] file_path está vacío para archivo ID {file_id}")
            return JsonResponse({
                'success': False,
                'error': 'Ruta de archivo inválida'
            }, status=400)
        
        # Eliminar de MinIO con debug mejorado
        from .minio_service import enhanced_minio_service
        
        print(f"[DEBUG] Llamando enhanced_minio_service.delete_file('{file_entry.file_path}')")
        
        try:
            result = enhanced_minio_service.delete_file(file_entry.file_path)
            
            print(f"[DEBUG] Resultado de MinIO: {result}")
            
            if not result['success']:
                error_msg = result.get('error', 'Error desconocido')
                print(f"[ERROR] MinIO delete failed: {error_msg}")
                
                # Solo continuar si el archivo ya no existe
                if ('not found' in error_msg.lower() or 
                    'NoSuchKey' in error_msg or 
                    'nosuchkey' in error_msg.lower()):
                    print(f"[INFO] Archivo ya no existe en MinIO, continuando...")
                else:
                    return JsonResponse({
                        'success': False,
                        'error': f'Error eliminando de almacenamiento: {error_msg}'
                    }, status=500)
            else:
                print(f"[SUCCESS] Archivo eliminado de MinIO exitosamente")
                
        except Exception as e:
            print(f"[ERROR] Excepción eliminando de MinIO: {e}")
            import traceback
            traceback.print_exc()
            
            # Solo continuar si es error de archivo no encontrado
            if 'not found' not in str(e).lower():
                return JsonResponse({
                    'success': False,
                    'error': f'Error eliminando de almacenamiento: {str(e)}'
                }, status=500)
        
        # Si llegamos aquí, proceder a eliminar de BD
        filename = file_entry.title
        file_entry.delete()
        
        print(f"[SUCCESS] Archivo eliminado de BD: {filename}")
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_deleted',
            title='Archivo eliminado',
            description=f'Archivo {filename} eliminado permanentemente',
            severity='warning'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Archivo "{filename}" eliminado exitosamente'
        })
        
    except Exception as e:
        print(f"[ERROR] Error general eliminando archivo: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def delete_all_files_combined(request):
    """
    Eliminar todos los archivos del usuario con manejo robusto mejorado
    """
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password', '').strip()
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener todos los archivos del usuario
        user_files = EncryptedFile.objects.filter(user=request.user)
        
        if not user_files.exists():
            return JsonResponse({
                'success': True,
                'message': 'No hay archivos para eliminar',
                'stats': {
                    'deleted_count': 0,
                    'error_count': 0
                }
            })
        
        deleted_count = 0
        errors = []
        total_files = user_files.count()
        
        # Eliminar cada archivo
        from .minio_service import enhanced_minio_service
        
        for file_entry in user_files:
            try:
                # Eliminar de MinIO
                result = enhanced_minio_service.delete_file(file_entry.file_path)
                
                if result['success'] or 'not found' in result.get('error', '').lower():
                    # Eliminar de BD si MinIO fue exitoso o archivo ya no existe
                    file_entry.delete()
                    deleted_count += 1
                    print(f"[DEBUG] Eliminado: {file_entry.title}")
                else:
                    errors.append({
                        'file': file_entry.title,
                        'error': result.get('error', 'Error desconocido')
                    })
                
            except Exception as e:
                error_msg = f"Error eliminando {file_entry.title}: {str(e)}"
                print(f"[ERROR] {error_msg}")
                errors.append({
                    'file': file_entry.title,
                    'error': str(e)
                })
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_deleted',
            title='Eliminación masiva de archivos',
            description=f'{deleted_count}/{total_files} archivos eliminados. {len(errors)} errores.',
            severity='warning' if errors else 'success'
        )
        
        # Preparar respuesta
        response_data = {
            'success': deleted_count > 0,
            'message': f'{deleted_count} de {total_files} archivos eliminados',
            'stats': {
                'total_files': total_files,
                'deleted_count': deleted_count,
                'error_count': len(errors)
            }
        }
        
        if errors:
            response_data['errors'] = errors
            response_data['partial_success'] = True
            
        # Status code apropiado
        status_code = 200 if not errors else 207  # 207 Multi-Status para éxito parcial
        
        return JsonResponse(response_data, status=status_code)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"[ERROR] Error eliminando todos los archivos: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)


# ==========================================
# FUNCIÓN AUXILIAR PARA AUTO-DETECCIÓN DE TIPO DE ENCRIPTACIÓN
# ==========================================

def detect_encryption_type(file_entry):
    """
    Detecta el tipo de encriptación basado en los metadatos del archivo
    """
    try:
        from .minio_service import enhanced_minio_service
        
        # Intentar obtener metadatos de MinIO
        info_result = enhanced_minio_service.get_file_info(file_entry.file_path)
        
        if info_result['success']:
            metadata = info_result['info'].get('metadata', {})
            
            # Verificar indicadores de doble encriptación
            if metadata.get('double_encrypted') == 'True':
                return 'double'
            elif metadata.get('simple_encryption') == 'True':
                return 'fernet'
            elif file_entry.algorithm == 'Fernet':
                return 'fernet'
            elif metadata.get('single_encrypted') == 'True':
                return 'single'
        
        # Fallback basado en datos del modelo
        if file_entry.algorithm == 'Fernet':
            return 'fernet'
        elif file_entry.encrypted_key == 'fernet_key_derived':
            return 'fernet'
        else:
            return 'single'  # Asumir encriptación simple por defecto
            
    except Exception as e:
        print(f"[WARNING] Error detectando tipo de encriptación: {e}")
        # Fallback seguro
        return 'single' if file_entry.algorithm != 'Fernet' else 'fernet'



# ==========================================
# FUNCIÓN AUXILIAR PARA ESTADÍSTICAS MEJORADAS
# ==========================================

@login_required
def api_files_stats_combined(request):
    """API para estadísticas detalladas incluyendo tipos de encriptación"""
    try:
        user_files = EncryptedFile.objects.filter(user=request.user)
        
        if not user_files.exists():
            return JsonResponse({
                'success': True,
                'stats': {
                    'total_files': 0,
                    'total_size': 0,
                    'encryption_types': {},
                    'algorithms_used': [],
                    'recent_uploads': 0
                }
            })
        
        from .minio_service import enhanced_minio_service
        
        total_size = 0
        algorithms = []
        encryption_types = {'single': 0, 'double': 0}
        successful_reads = 0
        
        for file in user_files:
            algorithms.append(file.algorithm)
            
            # Detectar tipo de encriptación
            enc_type = detect_encryption_type(file)
            encryption_types[enc_type] += 1
            
            try:
                info_result = enhanced_minio_service.get_file_info(file.file_path)
                
                if info_result['success']:
                    total_size += info_result['info']['size']
                    successful_reads += 1
                    
            except Exception:
                continue
        
        # Archivos recientes (últimos 7 días)
        recent_uploads = user_files.filter(
            uploaded_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total_files': user_files.count(),
                'total_size': total_size,
                'total_size_formatted': format_file_size(total_size),
                'encryption_types': encryption_types,
                'algorithms_used': list(set(algorithms)),
                'recent_uploads': recent_uploads,
                'sync_success_rate': f"{(successful_reads/user_files.count()*100):.1f}%" if user_files.count() > 0 else "0%",
                'algorithm_distribution': dict(Counter(algorithms))
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo estadísticas',
            'details': str(e)
        }, status=500)
        
        
# ==========================================
# VISTAS PARA MANEJO DE VAULTS
# ==========================================        
        
@login_required
@require_http_methods(["GET"])
def api_vaults(request):
    """API para obtener todos los vaults del usuario"""
    try:
        vaults = Vault.objects.filter(user=request.user)
        
        vaults_data = []
        for vault in vaults:
            vault_data = {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count(),
                'created_at': vault.created_at.isoformat(),
                'updated_at': vault.updated_at.isoformat()
            }
            vaults_data.append(vault_data)
        
        # Agregar información de contraseñas sin vault
        unvaulted_count = PasswordEntry.objects.filter(user=request.user, vault__isnull=True).count()
        
        return JsonResponse({
            'success': True,
            'vaults': vaults_data,
            'unvaulted_passwords': unvaulted_count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo vaults',
            'details': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_create_vault(request):
    """API para crear un nuevo vault"""
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        color = data.get('color', 'blue')
        is_private = data.get('is_private', False)
        vault_password = data.get('vault_password', '').strip() if is_private else None
        
        # Validaciones
        if not name:
            return JsonResponse({
                'success': False,
                'error': 'El nombre del vault es requerido'
            }, status=400)
        
        if len(name) > 100:
            return JsonResponse({
                'success': False,
                'error': 'El nombre del vault no puede exceder 100 caracteres'
            }, status=400)
        
        # Verificar que no existe otro vault con el mismo nombre
        if Vault.objects.filter(user=request.user, name=name).exists():
            return JsonResponse({
                'success': False,
                'error': 'Ya tienes un vault con ese nombre'
            }, status=400)
        
        # Validar color
        valid_colors = [choice[0] for choice in Vault.VAULT_COLORS]
        if color not in valid_colors:
            return JsonResponse({
                'success': False,
                'error': 'Color de vault inválido'
            }, status=400)
        
        # Para vaults privados, validar contraseña
        if is_private:
            if not vault_password:
                return JsonResponse({
                    'success': False,
                    'error': 'Los vaults privados requieren una contraseña'
                }, status=400)
            
            if len(vault_password) < 6:
                return JsonResponse({
                    'success': False,
                    'error': 'La contraseña del vault debe tener al menos 6 caracteres'
                }, status=400)
        
        # Crear el vault
        vault = Vault.objects.create(
            user=request.user,
            name=name,
            description=description,
            color=color,
            is_private=is_private
        )
        
        # Establecer contraseña si es privado
        if is_private and vault_password:
            vault.set_vault_password(vault_password)
            vault.save()
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_created',
            title='Vault creado',
            description=f'Vault "{name}" {"(privado)" if is_private else "(público)"} creado',
            severity='success',
            related_obj=vault
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Vault creado exitosamente',
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': 0,
                'created_at': vault.created_at.isoformat()
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error creando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_update_vault(request, vault_id):
    """API para actualizar un vault existente"""
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        color = data.get('color', 'blue')
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Validaciones
        if not name:
            return JsonResponse({
                'success': False,
                'error': 'El nombre del vault es requerido'
            }, status=400)
        
        # Verificar nombre único (excluyendo el actual)
        if Vault.objects.filter(user=request.user, name=name).exclude(id=vault_id).exists():
            return JsonResponse({
                'success': False,
                'error': 'Ya tienes un vault con ese nombre'
            }, status=400)
        
        # Validar color
        valid_colors = [choice[0] for choice in Vault.VAULT_COLORS]
        if color not in valid_colors:
            return JsonResponse({
                'success': False,
                'error': 'Color de vault inválido'
            }, status=400)
        
        # Actualizar campos
        vault.name = name
        vault.description = description
        vault.color = color
        vault.save()
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_updated',
            title='Vault actualizado',
            description=f'Vault "{name}" actualizado',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Vault actualizado exitosamente',
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count(),
                'updated_at': vault.updated_at.isoformat()
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error actualizando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_delete_vault(request, vault_id):
    """API para eliminar un vault"""
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password', '').strip()
        move_passwords_to_vault = data.get('move_passwords_to_vault')  # ID del vault destino o null
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Contar contraseñas en el vault
        passwords_in_vault = vault.passwords.all()
        password_count = passwords_in_vault.count()
        
        # Manejar contraseñas del vault que se va a eliminar
        if password_count > 0:
            if move_passwords_to_vault:
                # Mover a otro vault
                try:
                    destination_vault = Vault.objects.get(id=move_passwords_to_vault, user=request.user)
                    passwords_in_vault.update(vault=destination_vault)
                    action_description = f"movidas a vault '{destination_vault.name}'"
                except Vault.DoesNotExist:
                    return JsonResponse({
                        'success': False,
                        'error': 'Vault destino no encontrado'
                    }, status=404)
            else:
                # Mover a "sin vault" (null)
                passwords_in_vault.update(vault=None)
                action_description = "movidas a 'Todas las contraseñas'"
        else:
            action_description = "no había contraseñas"
        
        vault_name = vault.name
        vault.delete()
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_deleted',
            title='Vault eliminado',
            description=f'Vault "{vault_name}" eliminado - {password_count} contraseñas {action_description}',
            severity='warning'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Vault "{vault_name}" eliminado exitosamente',
            'stats': {
                'passwords_moved': password_count,
                'destination': destination_vault.name if move_passwords_to_vault else 'Todas las contraseñas'
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error eliminando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_unlock_vault(request, vault_id):
    """API para desbloquear un vault privado"""
    try:
        data = json.loads(request.body)
        vault_password = data.get('vault_password', '').strip()
        
        if not vault_password:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña del vault requerida'
            }, status=400)
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Si no es privado, no necesita desbloquearse
        if not vault.is_private:
            return JsonResponse({
                'success': True,
                'message': 'Vault público, no requiere desbloqueo'
            })
        
        # Verificar contraseña del vault
        if not vault.verify_vault_password(vault_password):
            return JsonResponse({
                'success': False,
                'error': 'Contraseña del vault incorrecta'
            }, status=400)
        
        return JsonResponse({
            'success': True,
            'message': f'Vault "{vault.name}" desbloqueado exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error desbloqueando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_vault_passwords(request, vault_id):
    """API para obtener contraseñas de un vault específico"""
    try:
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Obtener contraseñas del vault
        passwords = PasswordEntry.objects.filter(user=request.user, vault=vault)
        
        passwords_data = []
        for pwd in passwords:
            passwords_data.append({
                'id': pwd.id,
                'website': pwd.website,
                'username': pwd.username,
                'encryption_algorithm': pwd.encryption_algorithm,
                'created_at': pwd.created_at.isoformat(),
                'updated_at': pwd.updated_at.isoformat()
            })
        
        return JsonResponse({
            'success': True,
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private
            },
            'passwords': passwords_data,
            'count': len(passwords_data)
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo contraseñas del vault',
            'details': str(e)
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_unvaulted_passwords(request):
    """API para obtener contraseñas que no están en ningún vault"""
    try:
        passwords = PasswordEntry.objects.filter(user=request.user, vault__isnull=True)
        
        passwords_data = []
        for pwd in passwords:
            passwords_data.append({
                'id': pwd.id,
                'website': pwd.website,
                'username': pwd.username,
                'encryption_algorithm': pwd.encryption_algorithm,
                'created_at': pwd.created_at.isoformat(),
                'updated_at': pwd.updated_at.isoformat()
            })
        
        return JsonResponse({
            'success': True,
            'passwords': passwords_data,
            'count': len(passwords_data)
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo contraseñas sin vault',
            'details': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_move_password_to_vault(request):
    """API para mover una contraseña a un vault diferente"""
    try:
        data = json.loads(request.body)
        password_id = data.get('password_id')
        vault_id = data.get('vault_id')  # Puede ser null para remover de vault
        vault_password = data.get('vault_password', '').strip()  # Solo si el vault destino es privado
        
        if not password_id:
            return JsonResponse({
                'success': False,
                'error': 'ID de contraseña requerido'
            }, status=400)
        
        # Obtener la contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
        
        # Determinar vault destino
        destination_vault = None
        if vault_id:
            try:
                destination_vault = Vault.objects.get(id=vault_id, user=request.user)
                
                # Si el vault destino es privado, verificar contraseña
                if destination_vault.is_private:
                    if not vault_password:
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault requerida'
                        }, status=400)
                    
                    if not destination_vault.verify_vault_password(vault_password):
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault incorrecta'
                        }, status=400)
                
            except Vault.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Vault destino no encontrado'
                }, status=404)
        
        # Actualizar la contraseña
        old_vault_name = password_entry.vault.name if password_entry.vault else 'Sin vault'
        password_entry.vault = destination_vault
        password_entry.save()
        
        new_vault_name = destination_vault.name if destination_vault else 'Sin vault'
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='password_moved',
            title='Contraseña movida entre vaults',
            description=f'Contraseña de {password_entry.website} movida de "{old_vault_name}" a "{new_vault_name}"',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Contraseña movida a "{new_vault_name}" exitosamente',
            'moved_from': old_vault_name,
            'moved_to': new_vault_name
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error moviendo contraseña: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)        
        
        
def add_password_with_vault_support(request):
    """Versión modificada de add_password que soporta vaults"""
    try:
        data = json.loads(request.body)
        website = data.get('website', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        algorithm = data.get('algorithm', 'AES')
        vault_id = data.get('vault_id')  # Nuevo campo
        vault_password = data.get('vault_password', '').strip()  # Si el vault es privado
        
        # Validaciones básicas
        if not website:
            return JsonResponse({
                'success': False,
                'error': 'El sitio web es requerido'
            }, status=400)
        
        if not username:
            return JsonResponse({
                'success': False,
                'error': 'El nombre de usuario es requerido'
            }, status=400)
        
        if not password:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña es requerida'
            }, status=400)
        
        if len(password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña debe tener al menos 8 caracteres'
            }, status=400)
        
        if algorithm not in ['AES', 'ChaCha20']:
            return JsonResponse({
                'success': False,
                'error': 'Algoritmo de encriptación inválido'
            }, status=400)
        
        # Limpiar website URL (remover protocolo si existe)
        clean_website = website.replace('https://', '').replace('http://', '').replace('www.', '')
        
        # Obtener master key
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
            
        # Nueva validación para vault
        vault = None
        if vault_id:
            try:
                vault = Vault.objects.get(id=vault_id, user=request.user)
                
                # Si el vault es privado, verificar contraseña
                if vault.is_private:
                    if not vault_password:
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault requerida'
                        }, status=400)
                    
                    if not vault.verify_vault_password(vault_password):
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault incorrecta'
                        }, status=400)
                        
            except Vault.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Vault no encontrado'
                }, status=400)
                
        # Encriptar contraseña
        encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
            password, master_key, algorithm
        )
        
        # Crear entrada con vault (resto del código igual)
        password_entry = PasswordEntry.objects.create(
            user=request.user,
            website=clean_website,
            username=username,
            encrypted_password=encrypted_password,
            encryption_algorithm=algorithm,
            iv_or_nonce=iv_or_nonce,
            encrypted_key=encrypted_key,
            salt=entry_salt,
            vault=vault  # Nuevo campo
        )
        
        # Log modificado
        vault_info = f' en vault "{vault.name}"' if vault else ''
        
        log_activity(
            user=request.user,
            activity_type='password_created',
            title='Nueva contraseña creada',
            description=f'Contraseña creada para {clean_website}{vault_info}',
            severity='success',
            related_obj=password_entry
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Contraseña creada exitosamente',
            'password_id': password_entry.id,
            'vault': vault.name if vault else None
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error creating password: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)
        
@login_required
@require_http_methods(["GET"])
def api_vault_stats(request):
    """API para estadísticas generales de vaults del usuario"""
    try:
        user_vaults = Vault.objects.filter(user=request.user)
        total_passwords = PasswordEntry.objects.filter(user=request.user).count()
        
        stats = {
            'total_vaults': user_vaults.count(),
            'private_vaults': user_vaults.filter(is_private=True).count(),
            'public_vaults': user_vaults.filter(is_private=False).count(),
            'total_passwords': total_passwords,
            'unvaulted_passwords': PasswordEntry.objects.filter(user=request.user, vault__isnull=True).count(),
            'vaulted_passwords': PasswordEntry.objects.filter(user=request.user, vault__isnull=False).count(),
            'vault_colors_used': list(user_vaults.values_list('color', flat=True).distinct()),
            'largest_vault': None,
            'most_used_color': None
        }
        
        # Encontrar el vault más grande
        if user_vaults.exists():
            vault_sizes = []
            for vault in user_vaults:
                count = vault.get_password_count()
                vault_sizes.append({
                    'vault_name': vault.name,
                    'password_count': count
                })
            
            if vault_sizes:
                largest = max(vault_sizes, key=lambda x: x['password_count'])
                stats['largest_vault'] = largest
            
            # Color más usado
            from collections import Counter
            colors = list(user_vaults.values_list('color', flat=True))
            if colors:
                color_counts = Counter(colors)
                stats['most_used_color'] = color_counts.most_common(1)[0][0]
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo estadísticas de vaults',
            'details': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_change_vault_password(request, vault_id):
    """API para cambiar la contraseña de un vault privado"""
    try:
        data = json.loads(request.body)
        current_vault_password = data.get('current_vault_password', '').strip()
        new_vault_password = data.get('new_vault_password', '').strip()
        master_password = data.get('master_password', '').strip()
        
        if not all([current_vault_password, new_vault_password, master_password]):
            return JsonResponse({
                'success': False,
                'error': 'Todas las contraseñas son requeridas'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Verificar que es privado
        if not vault.is_private:
            return JsonResponse({
                'success': False,
                'error': 'Solo los vaults privados tienen contraseña'
            }, status=400)
        
        # Verificar contraseña actual
        if not vault.verify_vault_password(current_vault_password):
            return JsonResponse({
                'success': False,
                'error': 'Contraseña actual del vault incorrecta'
            }, status=400)
        
        # Validar nueva contraseña
        if len(new_vault_password) < 6:
            return JsonResponse({
                'success': False,
                'error': 'La nueva contraseña debe tener al menos 6 caracteres'
            }, status=400)
        
        # Cambiar contraseña
        vault.set_vault_password(new_vault_password)
        vault.save()
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_updated',
            title='Contraseña de vault cambiada',
            description=f'Contraseña del vault "{vault.name}" actualizada',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Contraseña del vault "{vault.name}" cambiada exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error cambiando contraseña de vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_convert_vault_privacy(request, vault_id):
    """API para convertir un vault entre público y privado"""
    try:
        data = json.loads(request.body)
        make_private = data.get('make_private', False)
        vault_password = data.get('vault_password', '').strip() if make_private else None
        master_password = data.get('master_password', '').strip()
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Verificar que hay cambio real
        if vault.is_private == make_private:
            status_text = "privado" if make_private else "público"
            return JsonResponse({
                'success': False,
                'error': f'El vault ya es {status_text}'
            }, status=400)
        
        # Si se convierte a privado, validar contraseña
        if make_private:
            if not vault_password:
                return JsonResponse({
                    'success': False,
                    'error': 'Contraseña del vault requerida para hacerlo privado'
                }, status=400)
            
            if len(vault_password) < 6:
                return JsonResponse({
                    'success': False,
                    'error': 'La contraseña del vault debe tener al menos 6 caracteres'
                }, status=400)
            
            # Establecer como privado
            vault.is_private = True
            vault.set_vault_password(vault_password)
        else:
            # Convertir a público
            vault.is_private = False
            vault.vault_password_hash = None
            vault.vault_salt = None
        
        vault.save()
        
        action_text = "convertido a privado" if make_private else "convertido a público"
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_updated',
            title='Privacidad de vault cambiada',
            description=f'Vault "{vault.name}" {action_text}',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Vault "{vault.name}" {action_text} exitosamente',
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'is_private': vault.is_private
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error cambiando privacidad de vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_batch_move_passwords(request):
    """API para mover múltiples contraseñas a un vault de una vez"""
    try:
        data = json.loads(request.body)
        password_ids = data.get('password_ids', [])
        destination_vault_id = data.get('destination_vault_id')  # Puede ser null
        vault_password = data.get('vault_password', '').strip()
        
        if not password_ids:
            return JsonResponse({
                'success': False,
                'error': 'Lista de contraseñas requerida'
            }, status=400)
        
        if len(password_ids) > 50:  # Límite razonable
            return JsonResponse({
                'success': False,
                'error': 'Máximo 50 contraseñas por operación'
            }, status=400)
        
        # Obtener contraseñas
        passwords = PasswordEntry.objects.filter(id__in=password_ids, user=request.user)
        
        if passwords.count() != len(password_ids):
            return JsonResponse({
                'success': False,
                'error': 'Algunas contraseñas no fueron encontradas'
            }, status=404)
        
        # Determinar vault destino
        destination_vault = None
        if destination_vault_id:
            try:
                destination_vault = Vault.objects.get(id=destination_vault_id, user=request.user)
                
                # Si es privado, verificar contraseña
                if destination_vault.is_private:
                    if not vault_password:
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault destino requerida'
                        }, status=400)
                    
                    if not destination_vault.verify_vault_password(vault_password):
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault destino incorrecta'
                        }, status=400)
                        
            except Vault.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Vault destino no encontrado'
                }, status=404)
        
        # Realizar el movimiento
        moved_count = 0
        vault_origins = []
        
        for password_entry in passwords:
            old_vault_name = password_entry.vault.name if password_entry.vault else 'Sin vault'
            vault_origins.append(old_vault_name)
            
            password_entry.vault = destination_vault
            password_entry.save()
            moved_count += 1
        
        new_vault_name = destination_vault.name if destination_vault else 'Sin vault'
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='password_moved',
            title='Movimiento masivo de contraseñas',
            description=f'{moved_count} contraseñas movidas a "{new_vault_name}"',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'{moved_count} contraseñas movidas a "{new_vault_name}" exitosamente',
            'stats': {
                'moved_count': moved_count,
                'destination': new_vault_name,
                'origins': list(set(vault_origins))
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error en movimiento masivo: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_vault_search(request):
    """API para buscar vaults y contraseñas dentro de vaults"""
    try:
        query = request.GET.get('q', '').strip()
        vault_id = request.GET.get('vault_id')
        
        if not query:
            return JsonResponse({
                'success': False,
                'error': 'Query de búsqueda requerida'
            }, status=400)
        
        results = {
            'vaults': [],
            'passwords': [],
            'query': query
        }
        
        # Buscar vaults por nombre
        matching_vaults = Vault.objects.filter(
            user=request.user,
            name__icontains=query
        )
        
        for vault in matching_vaults:
            results['vaults'].append({
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count()
            })
        
        # Buscar contraseñas
        password_filter = PasswordEntry.objects.filter(user=request.user)
        
        # Si se especifica un vault, buscar solo en ese vault
        if vault_id:
            if vault_id == 'unvaulted':
                password_filter = password_filter.filter(vault__isnull=True)
            else:
                try:
                    vault_id_int = int(vault_id)
                    password_filter = password_filter.filter(vault_id=vault_id_int)
                except ValueError:
                    return JsonResponse({
                        'success': False,
                        'error': 'ID de vault inválido'
                    }, status=400)
        
        # Buscar por website o username
        matching_passwords = password_filter.filter(
            Vault.Q(website__icontains=query) | 
            Vault.Q(username__icontains=query)
        )
        
        for password in matching_passwords:
            results['passwords'].append({
                'id': password.id,
                'website': password.website,
                'username': password.username,
                'vault_id': password.vault_id,
                'vault_name': password.vault.name if password.vault else None,
                'created_at': password.created_at.isoformat()
            })
        
        return JsonResponse({
            'success': True,
            'results': results,
            'total_results': len(results['vaults']) + len(results['passwords'])
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error en la búsqueda',
            'details': str(e)
        }, status=500)


# ==========================================
# API MODIFICADA PARA CUENTAS CON SOPORTE DE VAULTS
# ==========================================

@login_required
def api_accounts_with_vaults(request):
    """API modificada para obtener cuentas del usuario con información de vaults"""
    vault_id = request.GET.get('vault_id')
    
    try:
        # Filtrar por vault si se especifica
        if vault_id:
            if vault_id == 'unvaulted':
                accounts = PasswordEntry.objects.filter(user=request.user, vault__isnull=True)
            else:
                try:
                    vault_id_int = int(vault_id)
                    accounts = PasswordEntry.objects.filter(user=request.user, vault_id=vault_id_int)
                except ValueError:
                    return JsonResponse({'error': 'ID de vault inválido'}, status=400)
        else:
            # Todas las cuentas
            accounts = PasswordEntry.objects.filter(user=request.user)
        
        data = []
        for acc in accounts:
            account_data = {
                'id': acc.id,
                'website': acc.website,
                'username': acc.username,
                'encryption_algorithm': acc.encryption_algorithm,
                'encrypted_password': acc.encrypted_password,
                'salt': acc.salt,
                'iv_or_nonce': acc.iv_or_nonce,
                'encrypted_key': acc.encrypted_key,
                'vault_id': acc.vault_id,
                'vault_name': acc.vault.name if acc.vault else None,
                'vault_color': acc.vault.color if acc.vault else None,
                'vault_is_private': acc.vault.is_private if acc.vault else False,
                'created_at': acc.created_at.isoformat(),
                'updated_at': acc.updated_at.isoformat()
            }
            data.append(account_data)
        
        return JsonResponse({'accounts': data})
        
    except Exception as e:
        return JsonResponse({
            'error': 'Error obteniendo cuentas',
            'details': str(e)
        }, status=500)


# ==========================================
# FUNCIONES AUXILIARES PARA VALIDACIÓN
# ==========================================

def validate_vault_access(vault, vault_password=None):
    """Valida si se puede acceder a un vault"""
    if not vault.is_private:
        return True, None
    
    if not vault_password:
        return False, "Contraseña del vault requerida"
    
    if not vault.verify_vault_password(vault_password):
        return False, "Contraseña del vault incorrecta"
    
    return True, None


def get_vault_summary(user):
    """Obtiene un resumen de vaults del usuario para el dashboard"""
    try:
        vaults = Vault.objects.filter(user=user)
        total_passwords = PasswordEntry.objects.filter(user=user).count()
        
        summary = {
            'total_vaults': vaults.count(),
            'private_vaults': vaults.filter(is_private=True).count(),
            'public_vaults': vaults.filter(is_private=False).count(),
            'unvaulted_passwords': PasswordEntry.objects.filter(user=user, vault__isnull=True).count(),
            'vaulted_passwords': total_passwords - PasswordEntry.objects.filter(user=user, vault__isnull=True).count(),
            'vault_list': []
        }
        
        for vault in vaults[:5]:  # Top 5 vaults
            summary['vault_list'].append({
                'id': vault.id,
                'name': vault.name,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count()
            })
        
        return summary
    except Exception as e:
        print(f"Error getting vault summary: {e}")
        return None


        
        
