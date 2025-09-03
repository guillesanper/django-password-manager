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
from base64 import urlsafe_b64encode

import os
import uuid
import json
import hashlib
import requests
import math
import re

from .models import PasswordEntry, MasterKey, EncryptedFile, UserSettings,ActivityLog
from .forms import UserRegisterForm, PasswordForm, EncryptedFileForm, PasswordUpdateForm, SettingsForm
from .encryption_utils import encrypt_password, decrypt_password, generate_passwords, encrypt_file, decrypt_file
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
    """API para estadísticas del dashboard"""
    try:
        passwords_count = PasswordEntry.objects.filter(user=request.user).count()
        files_count = EncryptedFile.objects.filter(user=request.user).count()
        
        # Para sesiones activas, por ahora hardcoded
        # TODO: Implementar modelo de sesiones real
        active_sessions = 1
        
        # Calcular score de seguridad basado en algoritmos usados
        strong_passwords = PasswordEntry.objects.filter(
            user=request.user, 
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        security_score = min(95, (strong_passwords / max(passwords_count, 1)) * 100)
        
        return JsonResponse({
            'passwords_count': passwords_count,
            'files_count': files_count,
            'active_sessions': active_sessions,
            'security_score': round(security_score)
        })
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
@require_http_methods(["POST"])
@csrf_protect
def upload_file(request):
    """Subir archivo encriptado usando MinIO"""
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
        
        # Leer el contenido del archivo
        file_data = uploaded_file.read()
        original_filename = uploaded_file.name
        
        # Generar nombre único para MinIO
        
        # Derivar master key
        master_key_bytes = master_key_entry.derive_master_key(master_password)
        
        # Subir archivo encriptado a MinIO
        from .minio_service import enhanced_minio_service
        
        result = enhanced_minio_service.upload_encrypted_file(
            file_data=file_data,
            original_filename=original_filename,
            user_id=request.user.id,
            master_key_bytes=master_key_bytes,
            user_algorithm=algorithm,
            enable_double_encryption=True
        )
        
        if not result['success']:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Error al subir el archivo')
            }, status=500)
        
        # Crear registro en la base de datos
        file_entry = EncryptedFile.objects.create(
            user=request.user,
            title=original_filename,
            algorithm=algorithm,
            salt=result['metadata']['user_salt'],
            iv_or_nonce=result['metadata']['user_salt'][:32],  # Usar parte del salt como IV
            encrypted_key=urlsafe_b64encode(master_key_bytes).decode(),
            file_path=result['object_path']
        )
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_uploaded',
            title='Archivo encriptado subido',
            description=f'Archivo {original_filename} encriptado con {algorithm}',
            severity='success',
            related_obj=file_entry
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Archivo subido exitosamente',
            'file': {
                'id': file_entry.id,
                'title': file_entry.title,
                'algorithm': file_entry.algorithm,
                'uploaded_at': file_entry.uploaded_at.isoformat()
            }
        })
        
    except Exception as e:
        print(f"Error uploading file to MinIO: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def download_file(request, file_id):
    """Descargar archivo desencriptado desde MinIO"""
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
        
        # Derivar master key
        master_key_bytes = master_key_entry.derive_master_key(master_password)
        
        # Extraer nombre del objeto de MinIO desde file_path
        object_name = file_entry.file_path
        
        # Descargar y desencriptar desde MinIO
        from .minio_service import enhanced_minio_service
        
        result = enhanced_minio_service.download_encrypted_file(
            object_name=object_name,
            user_id=request.user.id,
            master_key_bytes=master_key_bytes
        )
        
        if not result['success']:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Error al descargar el archivo')
            }, status=500)
        
        # Preparar respuesta con archivo
        decrypted_data = result['data']
        filename = result['metadata'].get('original_filename', file_entry.title)
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_downloaded',
            title='Archivo descargado',
            description=f'Archivo {filename} descargado y desencriptado',
            severity='info'
        )
        
        # Crear respuesta HTTP con el archivo
        response = HttpResponse(
            decrypted_data,
            content_type='application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Content-Length'] = len(decrypted_data)
        
        return response
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error downloading file from MinIO: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def delete_file(request, file_id):
    """Eliminar archivo de MinIO"""
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
        
        # Extraer nombre del objeto desde file_path
        object_name = file_entry.file_path.split('/')[-1]
        
        # Eliminar de MinIO
        from .minio_service import enhanced_minio_service
        
        result = enhanced_minio_service.delete_file(
            object_name=object_name,
            user_id=request.user.id
        )
        
        if not result['success']:
            return JsonResponse({
                'success': False,
                'error': result.get('error', 'Error al eliminar el archivo de MinIO')
            }, status=500)
        
        # Eliminar registro de la base de datos
        filename = file_entry.title
        file_entry.delete()
        
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
            'message': 'Archivo eliminado exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error deleting file from MinIO: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def delete_all_files(request):
    """Eliminar todos los archivos del usuario de MinIO"""
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
                'message': 'No hay archivos para eliminar'
            })
        
        deleted_count = 0
        errors = []
        
        # Eliminar cada archivo
        from .minio_service import enhanced_minio_service
        
        for file_entry in user_files:
            try:
                object_name = file_entry.file_path.split('/')[-1]
                
                # Eliminar de MinIO
                result = enhanced_minio_service.delete_file(
                    object_name=object_name,
                    user_id=request.user.id
                )
                
                if result['success']:
                    file_entry.delete()
                    deleted_count += 1
                else:
                    errors.append(f"Error eliminando {file_entry.title}: {result.get('error')}")
                
            except Exception as e:
                errors.append(f"Error eliminando {file_entry.title}: {str(e)}")
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_deleted',
            title='Eliminación masiva de archivos',
            description=f'{deleted_count} archivos eliminados. {len(errors)} errores.',
            severity='warning' if errors else 'success'
        )
        
        if errors:
            return JsonResponse({
                'success': False,
                'message': f'{deleted_count} archivos eliminados correctamente',
                'errors': errors
            }, status=207)  # 207 Multi-Status
        
        return JsonResponse({
            'success': True,
            'message': f'Todos los archivos ({deleted_count}) eliminados exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error deleting all files: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


# ==========================================
# API ACTUALIZADA PARA LISTAR ARCHIVOS CON MINIO
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
                # Si hay error obteniendo info de MinIO, incluir solo info básica
                data.append({
                    'id': file.id,
                    'title': file.title,
                    'algorithm': file.algorithm,
                    'uploaded_at': file.uploaded_at.isoformat(),
                    'updated_at': file.updated_at.isoformat(),
                    'file_path': file.file_path,
                    'minio_error': f'Error obteniendo info: {str(e)}'
                })
        
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