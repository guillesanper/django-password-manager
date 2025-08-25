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
from django.views import View
from django.db import IntegrityError

import os
import uuid
import json

from .models import PasswordEntry, MasterKey, EncryptedFile, UserSettings
from .forms import UserRegisterForm, PasswordForm, EncryptedFileForm, PasswordUpdateForm, SettingsForm
from .encryption_utils import encrypt_password, decrypt_password, generate_passwords, encrypt_file, decrypt_file


# ==========================================
# VISTA PRINCIPAL PARA REACT SPA
# ==========================================

def app_view(request):
    """Vista única que sirve la aplicación React"""
    return render(request, 'base.html')


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
def api_files(request):
    """API para obtener archivos del usuario"""
    files = EncryptedFile.objects.filter(user=request.user)
    data = [{
        'id': file.id,
        'title': file.title,
        'algorithm': file.algorithm,
        'uploaded_at': file.uploaded_at.isoformat(),
        'encrypted_key': file.encrypted_key,
        'salt': file.salt,
        'iv_or_nonce': file.iv_or_nonce,
        'file_path': file.file_path
    } for file in files]
    return JsonResponse({'files': data})


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

@login_required(login_url='login')
def add_password(request):
    """Crear nueva entrada de contraseña"""
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()

            password = form.cleaned_data['password']
            algorithm = form.cleaned_data['algorithm']
            
            encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(password, master_key, algorithm)
            
            password_entry = PasswordEntry.objects.create(
                user=request.user,
                website=form.cleaned_data['website'],
                username=form.cleaned_data['username'],
                encrypted_password=encrypted_password,
                encryption_algorithm=algorithm,
                iv_or_nonce=iv_or_nonce,
                encrypted_key=encrypted_key,
                salt=entry_salt
            )
            
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'message': 'Password created successfully'})
            return redirect('app')  # Redirige a la SPA

    else:
        form = PasswordForm()
    
    # Si no es AJAX, servir la SPA que manejará el formulario
    return app_view(request)


@login_required(login_url='login')
def delete_password(request, password_id):
    """Eliminar entrada de contraseña"""
    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                master_password = data.get('master_password')
            else:
                master_password = request.POST.get('master_password')
            
            if master_password:
                master_key_entry = get_object_or_404(MasterKey, user=request.user)
                if master_key_entry.verify_master_key(master_password):
                    password_entry = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
                    password_entry.delete()
                    
                    if request.headers.get('Accept') == 'application/json':
                        return JsonResponse({'success': True, 'message': 'Password deleted successfully'})
                    return redirect('app')
                else:
                    error_message = "Master password incorrecta."
            else:
                error_message = "Debe ingresar una master password."
            
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': error_message}, status=400)
                
        except json.JSONDecodeError:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    return app_view(request)


@login_required(login_url='login')
def update_password(request, pk):
    """Actualizar entrada de contraseña"""
    password_entry = get_object_or_404(PasswordEntry, id=pk, user=request.user)
    
    if request.method == 'POST':
        form = PasswordUpdateForm(request.POST, instance=password_entry)
        if form.is_valid():
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()

            if form.cleaned_data['password']:
                password = form.cleaned_data['password']
                algorithm = form.cleaned_data['algorithm']
                
                encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
                    password, master_key, algorithm
                )
                
                password_entry.encrypted_password = encrypted_password
                password_entry.encrypted_key = encrypted_key
                password_entry.iv_or_nonce = iv_or_nonce
                password_entry.salt = entry_salt
                password_entry.encryption_algorithm = algorithm
            
            password_entry.website = form.cleaned_data['website']
            password_entry.username = form.cleaned_data['username']
            password_entry.save()

            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'message': 'Password updated successfully'})
            
            messages.success(request, 'Password entry updated successfully!')
            return redirect('app')
    
    return app_view(request)


# ==========================================
# VISTAS DE ARCHIVOS - MANTENER LÓGICA POST
# ==========================================

@login_required
def upload_file(request):
    """Subir archivo encriptado"""
    if request.method == 'POST':
        form = EncryptedFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['encrypted_file']
            original_file_name = uploaded_file.name

            fs = FileSystemStorage()
            temp_filename = fs.save(original_file_name, uploaded_file)
            temp_file_path = fs.path(temp_filename)

            encrypted_file_key, iv_or_nonce, salt = encrypt_file(temp_file_path, request.user.password.encode())

            encrypted_file_name = original_file_name + '.enc'
            encrypted_file_path = os.path.join(fs.location, encrypted_file_name)

            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            file_entry = EncryptedFile(
                user=request.user,
                title=original_file_name,
                file_path=encrypted_file_path,
                encrypted_key=encrypted_file_key,
                iv_or_nonce=iv_or_nonce,
                salt=salt,
                algorithm=form.cleaned_data['algorithm']
            )
            file_entry.save()

            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'message': 'File uploaded successfully'})
            return redirect('app')
    
    return app_view(request)


@login_required
def download_file(request, file_id):
    """Descargar archivo desencriptado"""
    file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
    
    encrypted_file_path = file_entry.file_path
    original_file_name = file_entry.title
    decrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), original_file_name)
    
    decrypt_file(
        encrypted_file_path=encrypted_file_path,
        master_key=request.user.password.encode(),
        encrypted_file_key=file_entry.encrypted_key,
        iv_or_nonce=file_entry.iv_or_nonce,
        entry_salt=file_entry.salt,
        algorithm=file_entry.algorithm,
        output_file_path=decrypted_file_path
    )

    with open(decrypted_file_path, 'rb') as f:
        file_content = f.read()

    response = HttpResponse(file_content, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename={os.path.basename(decrypted_file_path)}'
    
    if os.path.exists(decrypted_file_path):
        os.remove(decrypted_file_path)

    return response


@login_required
def delete_file(request, file_id):
    """Eliminar archivo"""
    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                master_password = data.get('master_password')
            else:
                master_password = request.POST.get('master_password')
            
            if master_password:
                master_key_entry = get_object_or_404(MasterKey, user=request.user)
                if master_key_entry.verify_master_key(master_password):
                    file_entry = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
                    
                    if os.path.exists(file_entry.file_path):
                        os.remove(file_entry.file_path)
                    
                    file_entry.delete()

                    if request.headers.get('Accept') == 'application/json':
                        return JsonResponse({'success': True, 'message': 'File deleted successfully'})
                    return redirect('app')
                else:
                    error_message = "Master password incorrecta."
            else:
                error_message = "Debe ingresar una master password."
            
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': error_message}, status=400)
                
        except json.JSONDecodeError:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': 'Invalid JSON'}, status=400)

    return app_view(request)


@login_required
def delete_all_files(request):
    """Eliminar todos los archivos"""
    if request.method == "POST":
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                master_password = data.get('master_password')
            else:
                master_password = request.POST.get('master_password')
            
            if master_password:
                master_key_entry = get_object_or_404(MasterKey, user=request.user)
                if master_key_entry.verify_master_key(master_password):
                    files = EncryptedFile.objects.filter(user=request.user)
                    for file in files:
                        if os.path.exists(file.file_path):
                            os.remove(file.file_path)
                        file.delete()
                    
                    if request.headers.get('Accept') == 'application/json':
                        return JsonResponse({'success': True, 'message': 'All files deleted successfully'})
                    return redirect('app')
                else:
                    error_message = "Contraseña maestra incorrecta."
            else:
                error_message = "Debe ingresar una master password."
            
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': error_message}, status=400)
                
        except json.JSONDecodeError:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': 'Invalid JSON'}, status=400)

    return redirect('app')


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


# Agregar estas vistas al archivo views.py existente

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
import json

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