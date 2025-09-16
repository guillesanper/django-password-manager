from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views import View
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.db import IntegrityError

import json

from ..models import UserSettings

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