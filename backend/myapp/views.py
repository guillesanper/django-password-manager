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

                # Crear configuraciones por defecto
                UserSettings.objects.create(
                    user=user,
                    theme='light',
                    require_password_modify=True,
                    require_password_delete=True,
                    notifications='enabled'
                )

                # Iniciar sesión automáticamente
                login(request, user)

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
            return JsonResponse({
                'success': False,
                'error': 'Error interno del servidor: ' + str(e)
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
# VISTAS ELIMINADAS (Ya no necesarias)
# ==========================================
# - view_unlocked_accs ❌ (reemplazada por api_unlock_all_accounts)
# - home ❌ (reemplazada por app_view)
# - viewAccs ❌ (reemplazada por api_accounts)  
# - password_generator ❌ (reemplazada por api_password_generator)
# - unlock_password ❌ (mantenida para compatibilidad, pero usar api_unlock_password)
# - file_list ❌ (reemplazada por api_files)