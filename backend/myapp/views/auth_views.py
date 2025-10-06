# myapp/auth_views.py - Vistas de autenticación con seguridad reforzada

import json
import logging
import time
from datetime import datetime, timedelta
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.middleware.csrf import get_token
from django.views import View
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from django.db import IntegrityError
from django.core.cache import cache
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated

from django_ratelimit.decorators import ratelimit

from ..models import UserSettings, SecurityEvent, ActivityLog, MasterKey
from ..validators import CustomPasswordValidator

# Configurar loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')
auth_logger = logging.getLogger('auth')


class SecureLoginView(APIView):
    permission_classes = [AllowAny]  # Login debe ser público
    """Vista de login con seguridad reforzada"""
    
    @method_decorator(csrf_protect)
    @method_decorator(ratelimit(key='ip', rate='15/5m', method='POST', block=True))  # 15 intentos por 5 min
    def post(self, request):
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        try:
            # Verificar rate limiting antes de procesar
            if self.is_rate_limited(ip_address):
                self.log_security_event(
                    None, ip_address, user_agent, 
                    'Rate limit exceeded', 'multiple_failed_logins'
                )
                return JsonResponse({
                    'success': False,
                    'error': 'Demasiados intentos fallidos. Intenta en 15 minutos.'
                }, status=429)
            
            data = json.loads(request.body)
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')

            # Validaciones básicas mejoradas
            validation_result = self.validate_login_input(email, password)
            if not validation_result['valid']:
                self.record_failed_attempt(ip_address)
                return JsonResponse({
                    'success': False,
                    'error': validation_result['error']
                }, status=400)

            # Verificar si la cuenta está bloqueada
            if self.is_account_locked(email):
                self.log_security_event(
                    None, ip_address, user_agent,
                    f'Attempt to access locked account: {email}', 'unauthorized_access'
                )
                return JsonResponse({
                    'success': False,
                    'error': 'Cuenta temporalmente bloqueada por seguridad'
                }, status=403)

            # Autenticar usuario
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                if not user.is_active:
                    self.log_security_event(
                        user, ip_address, user_agent,
                        'Attempt to login with inactive account', 'unauthorized_access'
                    )
                    return JsonResponse({
                        'success': False,
                        'error': 'La cuenta está desactivada'
                    }, status=403)

                # Login exitoso
                return self.handle_successful_login(request, user, ip_address, user_agent)
            
            else:
                # Login fallido
                return self.handle_failed_login(request, email, ip_address, user_agent)

        except json.JSONDecodeError:
            self.record_failed_attempt(ip_address)
            return JsonResponse({
                'success': False,
                'error': 'Datos JSON inválidos'
            }, status=400)
        except Exception as e:
            auth_logger.error(f"Login error: {str(e)} for IP: {ip_address}")
            return JsonResponse({
                'success': False,
                'error': 'Error interno del servidor'
            }, status=500)
    
    def validate_login_input(self, email, password):
        """Valida los datos de entrada del login"""
        if not email or not password:
            return {'valid': False, 'error': 'Email y contraseña son requeridos'}
        
        if len(email) > 254:  # Límite estándar de email
            return {'valid': False, 'error': 'Email demasiado largo'}
        
        if len(password) > 128:  # Prevenir DoS
            return {'valid': False, 'error': 'Contraseña demasiado larga'}
        
        # Validación básica de formato email
        import re
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            return {'valid': False, 'error': 'Formato de email inválido'}
        
        return {'valid': True}
    
    def is_rate_limited(self, ip_address):
        """Verifica si la IP está limitada por intentos fallidos"""
        cache_key = f"failed_login_attempts_{ip_address}"
        attempts = cache.get(cache_key, [])
        current_time = time.time()
        
        # Filtrar intentos de los últimos 15 minutos
        recent_attempts = [attempt for attempt in attempts if current_time - attempt < 900]
        
        return len(recent_attempts) >= 5
    
    def is_account_locked(self, email):
        """Verifica si la cuenta específica está bloqueada"""
        cache_key = f"locked_account_{email}"
        return cache.get(cache_key, False)
    
    def record_failed_attempt(self, ip_address, email=None):
        """Registra intento fallido"""
        # Rate limiting por IP
        cache_key = f"failed_login_attempts_{ip_address}"
        attempts = cache.get(cache_key, [])
        attempts.append(time.time())
        cache.set(cache_key, attempts, 900)  # 15 minutos
        
        # Si es para un email específico, también contar por cuenta
        if email:
            account_key = f"account_failed_attempts_{email}"
            account_attempts = cache.get(account_key, [])
            account_attempts.append(time.time())
            cache.set(account_key, account_attempts, 1800)  # 30 minutos
            
            # Bloquear cuenta después de 10 intentos fallidos
            recent_attempts = [a for a in account_attempts if time.time() - a < 1800]
            if len(recent_attempts) >= 10:
                lock_key = f"locked_account_{email}"
                cache.set(lock_key, True, 1800)  # Bloquear por 30 minutos
    
    def handle_successful_login(self, request, user, ip_address, user_agent):
        """Maneja login exitoso"""
        try:
            # Limpiar intentos fallidos
            cache_key = f"failed_login_attempts_{ip_address}"
            cache.delete(cache_key)
            
            account_key = f"account_failed_attempts_{user.email}"
            cache.delete(account_key)
            
            # Login tradicional de Django
            login(request, user)
            
            # Generar tokens JWT
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Agregar claims personalizados al token
            access_token['email'] = user.email
            access_token['ip'] = ip_address
            access_token['user_agent_hash'] = hash(user_agent) % 10000  # Hash corto para verificación
            
            # Crear o actualizar configuraciones de usuario
            user_settings, created = UserSettings.objects.get_or_create(
                user=user,
                defaults={
                    'theme': 'light',
                    'require_password_modify': True,
                    'require_password_delete': True,
                    'notifications': 'enabled'
                }
            )
            
            # Registrar actividad de login exitoso
            ActivityLog.objects.create(
                user=user,
                activity_type='login',
                title='Inicio de sesión exitoso',
                description=f'Login desde IP: {ip_address}',
                severity='success',
                ip_address=ip_address,
                user_agent=user_agent[:500]
            )
            
            auth_logger.info(f"Successful login for user: {user.username} from IP: {ip_address}")
            
            # Verificar si tiene clave maestra configurada
            has_master_key = hasattr(user, 'masterkey')
            
            return JsonResponse({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'firstName': user.first_name,
                    'lastName': user.last_name,
                    'isAuthenticated': True,
                    'hasMasterKey': has_master_key
                },
                'tokens': {
                    'access': str(access_token),
                    'refresh': str(refresh)
                }
            })
            
        except Exception as e:
            auth_logger.error(f"Error in successful login handling: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Error procesando login exitoso'
            }, status=500)
    
    def handle_failed_login(self, request, email, ip_address, user_agent):
        """Maneja login fallido"""
        # Registrar intento fallido
        self.record_failed_attempt(ip_address, email)
        
        # Log de seguridad
        self.log_security_event(
            None, ip_address, user_agent,
            f'Failed login attempt for email: {email}', 'failed_login'
        )
        
        auth_logger.warning(f"Failed login attempt for email: {email} from IP: {ip_address}")
        
        return JsonResponse({
            'success': False,
            'error': 'Email o contraseña incorrectos'
        }, status=400)
    
    def log_security_event(self, user, ip_address, user_agent, description, event_type):
        """Registra evento de seguridad"""
        try:
            SecurityEvent.objects.create(
                user=user,
                event_type=event_type,
                description=description,
                ip_address=ip_address,
                user_agent=user_agent[:500] if user_agent else '',
                additional_data={
                    'timestamp': datetime.now().isoformat(),
                    'endpoint': '/auth/login/'
                }
            )
        except Exception as e:
            security_logger.error(f"Failed to log security event: {e}")
    
    def get_client_ip(self, request):
        """Obtiene la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecureRegisterView(APIView):
    """Vista de registro con validaciones estrictas"""
    permission_classes = [AllowAny]  # Login debe ser público
    
    @method_decorator(csrf_protect)
    @method_decorator(ratelimit(key='ip', rate='8/hour', method='POST', block=True))  # 8 registros por hora
    def post(self, request):
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        try:
            # Rate limiting para registro
            if self.is_registration_rate_limited(ip_address):
                return JsonResponse({
                    'success': False,
                    'error': 'Demasiados registros desde esta IP. Intenta más tarde.'
                }, status=429)
            
            data = json.loads(request.body)
            first_name = data.get('first_name', '').strip()
            last_name = data.get('last_name', '').strip()
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')

            # Validaciones exhaustivas
            validation_result = self.validate_registration_data(
                first_name, last_name, email, password
            )
            
            if not validation_result['valid']:
                self.record_registration_attempt(ip_address)
                return JsonResponse({
                    'success': False,
                    'error': validation_result['error']
                }, status=400)

            # Verificar si el email ya existe
            if User.objects.filter(email=email).exists():
                self.record_registration_attempt(ip_address)
                # Log de intento de registro con email existente
                security_logger.warning(
                    f"Registration attempt with existing email: {email} from IP: {ip_address}"
                )
                return JsonResponse({
                    'success': False,
                    'error': 'Ya existe una cuenta con este email'
                }, status=400)

            # Validar contraseña con validadores de Django
            try:
                validate_password(password)
            except ValidationError as e:
                return JsonResponse({
                    'success': False,
                    'error': '. '.join(e.messages)
                }, status=400)

            # Generar username único
            username = self.generate_unique_username(email)

            try:
                # Crear usuario
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )

                # Autenticar y hacer login inmediatamente
                authenticated_user = authenticate(request, email=email, password=password)
                
                if authenticated_user:
                    login(request, authenticated_user)
                    
                    # Generar tokens JWT
                    refresh = RefreshToken.for_user(authenticated_user)
                    access_token = refresh.access_token
                    
                    # Agregar claims personalizados
                    access_token['email'] = authenticated_user.email
                    access_token['ip'] = ip_address
                    
                    # Crear configuraciones por defecto
                    UserSettings.objects.create(
                        user=authenticated_user,
                        theme='light',
                        require_password_modify=True,
                        require_password_delete=True,
                        notifications='enabled'
                    )
                    
                    # Log de registro exitoso
                    ActivityLog.objects.create(
                        user=authenticated_user,
                        activity_type='login',  # Registro implica login
                        title='Cuenta creada y sesión iniciada',
                        description=f'Registro exitoso desde IP: {ip_address}',
                        severity='success',
                        ip_address=ip_address,
                        user_agent=user_agent[:500]
                    )
                    
                    auth_logger.info(f"Successful registration for user: {authenticated_user.username} from IP: {ip_address}")

                    return JsonResponse({
                        'success': True,
                        'user': {
                            'id': authenticated_user.id,
                            'username': authenticated_user.username,
                            'email': authenticated_user.email,
                            'firstName': authenticated_user.first_name,
                            'lastName': authenticated_user.last_name,
                            'isAuthenticated': True,
                            'hasMasterKey': False  # Nuevo usuario nunca tiene master key
                        },
                        'tokens': {
                            'access': str(access_token),
                            'refresh': str(refresh)
                        }
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'error': 'Error en la autenticación automática'
                    }, status=400)

            except IntegrityError as e:
                auth_logger.error(f"Registration integrity error: {str(e)}")
                return JsonResponse({
                    'success': False,
                    'error': 'Error al crear la cuenta. El email ya está en uso.'
                }, status=400)

        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Datos JSON inválidos'
            }, status=400)
        except Exception as e:
            auth_logger.error(f"Registration error: {str(e)} for IP: {ip_address}")
            return JsonResponse({
                'success': False,
                'error': 'Error interno del servidor'
            }, status=500)
    
    def validate_registration_data(self, first_name, last_name, email, password):
        """Valida exhaustivamente los datos de registro"""
        # Validar nombres
        if not first_name or not last_name:
            return {'valid': False, 'error': 'Nombre y apellido son requeridos'}
        
        if len(first_name) < 2 or len(last_name) < 2:
            return {'valid': False, 'error': 'Nombre y apellido deben tener al menos 2 caracteres'}
        
        if len(first_name) > 30 or len(last_name) > 30:
            return {'valid': False, 'error': 'Nombre y apellido no pueden exceder 30 caracteres'}
        
        # Validar que solo contengan letras, espacios y caracteres acentuados
        import re
        name_pattern = r'^[a-zA-ZÀ-ÿ\s]+$'
        if not re.match(name_pattern, first_name) or not re.match(name_pattern, last_name):
            return {'valid': False, 'error': 'Nombre y apellido solo pueden contener letras'}
        
        # Validar email
        if not email:
            return {'valid': False, 'error': 'Email es requerido'}
        
        if len(email) > 254:
            return {'valid': False, 'error': 'Email demasiado largo'}
        
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            return {'valid': False, 'error': 'Formato de email inválido'}
        
        # Validar que no sea un dominio temporal conocido
        temp_domains = ['10minutemail.com', 'tempmail.org', 'guerrillamail.com']
        email_domain = email.split('@')[1].lower()
        if email_domain in temp_domains:
            return {'valid': False, 'error': 'No se permiten emails temporales'}
        
        # Validar contraseña
        if not password:
            return {'valid': False, 'error': 'Contraseña es requerida'}
        
        if len(password) < 12:  # Más estricto que el default
            return {'valid': False, 'error': 'La contraseña debe tener al menos 12 caracteres'}
        
        if len(password) > 128:
            return {'valid': False, 'error': 'Contraseña demasiado larga'}
        
        # Validar complejidad de contraseña
        if not self.is_password_complex(password):
            return {
                'valid': False, 
                'error': 'La contraseña debe contener al menos una mayúscula, una minúscula, un número y un símbolo'
            }
        
        return {'valid': True}
    
    def is_password_complex(self, password):
        """Verifica complejidad de contraseña"""
        import re
        
        has_upper = re.search(r'[A-Z]', password)
        has_lower = re.search(r'[a-z]', password)
        has_digit = re.search(r'\d', password)
        has_symbol = re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)
        
        return all([has_upper, has_lower, has_digit, has_symbol])
    
    def is_registration_rate_limited(self, ip_address):
        """Rate limiting para registro"""
        cache_key = f"registration_attempts_{ip_address}"
        attempts = cache.get(cache_key, [])
        current_time = time.time()
        
        # Filtrar intentos de la última hora
        recent_attempts = [attempt for attempt in attempts if current_time - attempt < 3600]
        
        return len(recent_attempts) >= 3  # Máximo 3 registros por hora por IP
    
    def record_registration_attempt(self, ip_address):
        """Registra intento de registro"""
        cache_key = f"registration_attempts_{ip_address}"
        attempts = cache.get(cache_key, [])
        attempts.append(time.time())
        cache.set(cache_key, attempts, 3600)
    
    def generate_unique_username(self, email):
        """Genera username único basado en email"""
        base_username = email.split('@')[0]
        # Limpiar caracteres especiales
        import re
        base_username = re.sub(r'[^a-zA-Z0-9]', '', base_username)
        
        if len(base_username) < 3:
            base_username = 'user'
        
        username = base_username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1
            
            # Prevenir loop infinito
            if counter > 1000:
                username = f"user{int(time.time())}"
                break
        
        return username
    
    def get_client_ip(self, request):
        """Obtiene la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecureLogoutView(APIView):
    """Vista de logout segura"""
    permission_classes= [IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    
    @method_decorator(csrf_protect)
    def post(self, request):
        try:
            user = request.user if request.user.is_authenticated else None
            ip_address = self.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            if user:
                # Registrar logout
                ActivityLog.objects.create(
                    user=user,
                    activity_type='logout',
                    title='Cierre de sesión',
                    description=f'Logout desde IP: {ip_address}',
                    severity='info',
                    ip_address=ip_address,
                    user_agent=user_agent[:500]
                )
                
                auth_logger.info(f"User logout: {user.username} from IP: {ip_address}")
            
            # Invalidar sesión de Django
            logout(request)
            
            # Para JWT, en el frontend deberán eliminar los tokens
            # También se puede implementar blacklist de tokens aquí si es necesario
            
            return JsonResponse({
                'success': True,
                'message': 'Sesión cerrada exitosamente'
            })
        except Exception as e:
            auth_logger.error(f"Logout error: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': 'Error al cerrar sesión'
            }, status=500)
    
    def get_client_ip(self, request):
        """Obtiene la IP real del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def check_auth_status(request):
    """
    Endpoint JWT para verificar estado de autenticación.
    Ahora usa JWT Authentication correctamente.
    """
    try:
        user = request.user
        
        # Verificar si tiene master key
        has_master_key = False
        try:
            from ..models import MasterKey
            has_master_key = hasattr(user, 'masterkey') and bool(user.masterkey.hashed_key)
        except Exception:
            pass
        
        return JsonResponse({
            'success': True,
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'isAuthenticated': True,
                'hasMasterKey': has_master_key
            }
        })
        
    except Exception as e:
        auth_logger.error(f"Error en check_auth_status: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Error verificando autenticación'
        }, status=500)
        
@api_view(['GET'])
@ensure_csrf_cookie  # Asegura que la cookie CSRF se establezca
def get_csrf_token(request):
    """
    Endpoint para obtener token CSRF - necesario para CORS
    """
    try:
        # Obtener el token CSRF
        token = get_token(request)
        
        # Log para debugging
        auth_logger.info(f"CSRF token generado para IP: {request.META.get('REMOTE_ADDR')}")
        
        return JsonResponse({
            'csrfToken': token,
            'success': True
        })
    except Exception as e:
        auth_logger.error(f"Error generando CSRF token: {str(e)}")
        return JsonResponse({
            'error': 'Error generando token CSRF',
            'success': False
        }, status=500)