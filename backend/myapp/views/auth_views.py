# myapp/auth_views.py - Vistas de autenticación con seguridad reforzada

import json
import logging
import time
from datetime import datetime, timedelta
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from django.middleware.csrf import get_token
from django.views import View
from django.http import JsonResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password
from django.db import IntegrityError
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone

from rest_framework_simplejwt.tokens import RefreshToken
from ..authentication import CookieJWTAuthentication, enforce_csrf
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated

from django_ratelimit.decorators import ratelimit

from ..models import UserSettings, SecurityEvent, ActivityLog, MasterKey
from ..validators import CustomPasswordValidator
from ..utils.cache_utils import (
    CacheUnavailable,
    lenient_delete,
    service_unavailable_response,
    strict_get,
    strict_set,
)
from ..utils.request_utils import get_client_ip
from ..utils.jwt_cookies import (
    clear_auth_cookies,
    get_refresh_from_cookie,
    set_auth_cookies,
)

# Configurar loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')
auth_logger = logging.getLogger('auth')


class SecureLoginView(APIView):
    permission_classes = [AllowAny]  # Login debe ser público
    """Vista de login con seguridad reforzada"""
    
    @method_decorator(ratelimit(key='ip', rate='15/5m', method='POST', block=True))  # 15 intentos por 5 min
    def post(self, request):
        # CSRF explícito en vez de @csrf_protect: éste, sobre una vista de DRF,
        # lee `request.POST` de la Request de DRF y consume el stream, de modo
        # que el `json.loads(request.body)` de abajo reventaba con
        # RawPostDataException (500). `enforce_csrf` opera sobre la request de
        # Django subyacente y no toca el cuerpo. Va fuera del try para que un
        # fallo de CSRF salga como 403 de DRF, no como el 500 genérico.
        enforce_csrf(request)

        ip_address = get_client_ip(request)
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
                    # El evento conserva el detalle: que alguien acierte la
                    # contraseña de una cuenta desactivada es exactamente lo que
                    # interesa ver en el registro forense.
                    self.log_security_event(
                        user, ip_address, user_agent,
                        'Attempt to login with inactive account', 'unauthorized_access'
                    )
                    # Pero hacia fuera es indistinguible de unas credenciales
                    # erróneas. Antes devolvía 403 "La cuenta está desactivada"
                    # frente al 400 genérico, así que una sola petición separaba
                    # "email no registrado" de "email registrado y desactivado":
                    # enumeración de cuentas por contenido de respuesta, la misma
                    # clase de fuga que A6 cierra por temporización.
                    #
                    # Se delega en handle_failed_login en lugar de copiar su
                    # respuesta: así coinciden también el estado, los contadores
                    # de bloqueo por IP y por cuenta, y el SecurityEvent de
                    # 'failed_login'. Indistinguible por construcción, no por
                    # mantener dos textos sincronizados a mano.
                    return self.handle_failed_login(request, email, ip_address, user_agent)

                # Login exitoso
                return self.handle_successful_login(request, user, ip_address, user_agent)
            
            else:
                # Login fallido
                return self.handle_failed_login(request, email, ip_address, user_agent)

        except CacheUnavailable:
            # FAIL-CLOSED (paso 19, M6). Sin caché no hay rate limiting por IP
            # ni bloqueo de cuenta, así que dejar pasar el login convertiría una
            # caída de Redis en fuerza bruta libre. Se deniega con 503, que es
            # distinguible de un 429 y le dice al cliente que reintente.
            #
            # Va ANTES del `except Exception` de abajo a propósito: si no, la
            # excepción caería en el manejador genérico y se serviría como un
            # 500 opaco, que es lo mismo que fallar cerrado por accidente en vez
            # de por decisión, y sin dejarlo escrito en los logs de seguridad.
            auth_logger.error(
                "Login denegado: caché no disponible (IP %s)", ip_address
            )
            return service_unavailable_response()
        except json.JSONDecodeError:
            # No se registra el intento: `record_failed_attempt` también
            # necesita la caché y volvería a estallar.
            try:
                self.record_failed_attempt(ip_address)
            except CacheUnavailable:
                pass
            return JsonResponse({
                'success': False,
                'error': 'Datos JSON inválidos'
            }, status=400)
        except Exception:
            auth_logger.exception("Login error for IP: %s", ip_address)
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
        """Verifica si la IP está limitada por intentos fallidos.

        Política de caché: STRICT (paso 19, M6). Si Redis no responde no se
        puede saber cuántos intentos lleva esta IP, y contestar "no está
        limitada" es justo lo que hacía el `IGNORE_EXCEPTIONS: True` anterior:
        fuerza bruta ilimitada contra el login, en silencio. Levanta
        `CacheUnavailable` y `post()` responde 503.
        """
        cache_key = f"failed_login_attempts_{ip_address}"
        attempts = strict_get(cache_key, [])
        current_time = time.time()
        
        # Filtrar intentos de los últimos 15 minutos
        recent_attempts = [attempt for attempt in attempts if current_time - attempt < 900]
        
        return len(recent_attempts) >= 5
    
    def is_account_locked(self, email):
        """Verifica si la cuenta específica está bloqueada.

        Política de caché: STRICT. El bloqueo de cuenta vive sólo aquí; sin
        caché, responder "no está bloqueada" levanta el bloqueo de todas las
        cuentas bloqueadas a la vez.
        """
        cache_key = f"locked_account_{email}"
        return strict_get(cache_key, False)
    
    def record_failed_attempt(self, ip_address, email=None):
        """Registra intento fallido"""
        # Rate limiting por IP
        cache_key = f"failed_login_attempts_{ip_address}"
        attempts = strict_get(cache_key, [])
        attempts.append(time.time())
        strict_set(cache_key, attempts, 900)  # 15 minutos
        
        # Si es para un email específico, también contar por cuenta
        if email:
            account_key = f"account_failed_attempts_{email}"
            account_attempts = strict_get(account_key, [])
            account_attempts.append(time.time())
            strict_set(account_key, account_attempts, 1800)  # 30 minutos
            
            # Bloquear cuenta después de 10 intentos fallidos
            recent_attempts = [a for a in account_attempts if time.time() - a < 1800]
            if len(recent_attempts) >= 10:
                lock_key = f"locked_account_{email}"
                strict_set(lock_key, True, 1800)  # Bloquear por 30 minutos
    
    def handle_successful_login(self, request, user, ip_address, user_agent):
        """Maneja login exitoso"""
        try:
            # Limpiar intentos fallidos
            cache_key = f"failed_login_attempts_{ip_address}"
            lenient_delete(cache_key)
            
            account_key = f"account_failed_attempts_{user.email}"
            lenient_delete(account_key)
            
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

            # Paso 8: los tokens ya NO viajan en el cuerpo. Salen como cookies
            # HttpOnly que el JavaScript no puede leer; el cuerpo sólo lleva los
            # datos del usuario para pintar la UI. Si se devolvieran también en
            # el cuerpo, el frontend podría volver a guardarlos en localStorage
            # y se reabriría A1.
            response = JsonResponse({
                'success': True,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'firstName': user.first_name,
                    'lastName': user.last_name,
                    'isAuthenticated': True,
                    'hasMasterKey': has_master_key
                }
            })
            return set_auth_cookies(response, access_token, refresh)
            
        except Exception:
            auth_logger.exception("Error in successful login handling")
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


class SecureRegisterView(APIView):
    """Vista de registro con validaciones estrictas"""
    permission_classes = [AllowAny]  # Login debe ser público
    
    @method_decorator(ratelimit(key='ip', rate='8/hour', method='POST', block=True))  # 8 registros por hora
    def post(self, request):
        # CSRF explícito, no @csrf_protect (ver SecureLoginView.post): éste
        # consumía el stream de la Request de DRF y hacía que
        # `json.loads(request.body)` diera 500. `enforce_csrf` no toca el cuerpo.
        enforce_csrf(request)

        ip_address = get_client_ip(request)
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

                    # Paso 8: tokens en cookies HttpOnly, no en el cuerpo (ver login).
                    response = JsonResponse({
                        'success': True,
                        'user': {
                            'id': authenticated_user.id,
                            'username': authenticated_user.username,
                            'email': authenticated_user.email,
                            'firstName': authenticated_user.first_name,
                            'lastName': authenticated_user.last_name,
                            'isAuthenticated': True,
                            'hasMasterKey': False  # Nuevo usuario nunca tiene master key
                        }
                    })
                    return set_auth_cookies(response, access_token, refresh)
                else:
                    return JsonResponse({
                        'success': False,
                        'error': 'Error en la autenticación automática'
                    }, status=400)

            except IntegrityError:
                auth_logger.exception("Registration integrity error")
                return JsonResponse({
                    'success': False,
                    'error': 'Error al crear la cuenta. El email ya está en uso.'
                }, status=400)

        except CacheUnavailable:
            # FAIL-CLOSED (paso 19, M6): sin caché no hay límite de registros
            # por IP, y el registro es el camino más barato para inundar la base
            # de usuarios. Antes del `except Exception`, que devolvería un 500.
            auth_logger.error(
                "Registro denegado: caché no disponible (IP %s)", ip_address
            )
            return service_unavailable_response()
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'error': 'Datos JSON inválidos'
            }, status=400)
        except Exception:
            auth_logger.exception("Registration error for IP: %s", ip_address)
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
        attempts = strict_get(cache_key, [])
        current_time = time.time()
        
        # Filtrar intentos de la última hora
        recent_attempts = [attempt for attempt in attempts if current_time - attempt < 3600]
        
        return len(recent_attempts) >= 3  # Máximo 3 registros por hora por IP
    
    def record_registration_attempt(self, ip_address):
        """Registra intento de registro"""
        cache_key = f"registration_attempts_{ip_address}"
        attempts = strict_get(cache_key, [])
        attempts.append(time.time())
        strict_set(cache_key, attempts, 3600)
    
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


class SecureLogoutView(APIView):
    """Vista de logout segura"""
    permission_classes= [IsAuthenticated]
    authentication_classes = [CookieJWTAuthentication]

    # Sin @csrf_protect: al estar autenticada por CookieJWTAuthentication, el
    # CSRF ya lo exige ésa (la cookie está presente). Además csrf_protect aquí
    # consumía el stream de DRF innecesariamente.
    def post(self, request):
        try:
            user = request.user if request.user.is_authenticated else None
            ip_address = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')

            # A5: hasta ahora el logout no invalidaba nada. `token_blacklist` está
            # instalado y ROTATE_REFRESH_TOKENS activo, pero sin llamar a
            # .blacklist() el refresh token seguía sirviendo 7 días después de
            # "cerrar sesión": bastaba haberlo copiado antes.
            revoked = self._revoke_refresh_tokens(request, user) if user else 0

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

                auth_logger.info(
                    f"User logout: {user.username} from IP: {ip_address} "
                    f"({revoked} refresh token(s) invalidados)"
                )

            # Invalidar sesión de Django
            logout(request)

            # Paso 8: borrar las cookies HttpOnly. Sin esto el navegador seguiría
            # enviando un access token válido hasta su expiración (60 min) pese al
            # "cierre de sesión".
            response = JsonResponse({
                'success': True,
                'message': 'Sesión cerrada exitosamente'
            })
            return clear_auth_cookies(response)
        except Exception:
            auth_logger.exception("Logout error")
            return JsonResponse({
                'success': False,
                'error': 'Error al cerrar sesión'
            }, status=500)

    def _revoke_refresh_tokens(self, request, user):
        """Invalida los refresh tokens del usuario. Devuelve cuántos.

        Dos caminos, en este orden:

        1. Si se puede identificar el `refresh` de ESTE dispositivo —desde el
           paso 8, la cookie HttpOnly; como respaldo, el cuerpo— se invalida
           sólo ese: es el logout preciso, que no toca las sesiones de otros
           dispositivos. **Se comprueba que el token sea de quien lo envía**;
           sin esa comprobación, cualquier usuario autenticado podría invalidar
           el refresh token de otro y echarlo de su sesión.
        2. Si no hay forma de identificarlo, se invalidan TODOS los del usuario
           que sigan vivos. Es la opción fail-closed: un cliente que calla no
           puede dejarse un token válido detrás. La contrapartida es que cerrar
           sesión así la cierra en todos los dispositivos; para cerrar una sola
           está la pantalla de sesiones. Con las cookies del paso 8 este camino
           deja de ser el habitual: el navegador siempre manda la cookie.

        Nota: esto sólo alcanza a los refresh. Un access token robado sigue
        siendo válido hasta que expire (ACCESS_TOKEN_LIFETIME, 60 min); es
        inherente a JWT sin estado y no lo arregla el blacklist.
        """
        # La cookie es la fuente primaria; el cuerpo queda como respaldo para
        # clientes que no sean navegador (curl, scripts de verificación).
        raw = get_refresh_from_cookie(request)
        if not raw and hasattr(request, 'data') and isinstance(request.data, dict):
            raw = request.data.get('refresh') or request.data.get('refresh_token')

        if raw:
            try:
                token = RefreshToken(raw)
                if str(token.get('user_id')) != str(user.id):
                    security_logger.warning(
                        f"Logout con refresh token ajeno: usuario {user.id} "
                        f"intentó invalidar el de {token.get('user_id')}"
                    )
                else:
                    token.blacklist()
                    return 1
            except TokenError:
                # Token ya expirado, ya invalidado o manipulado: no es motivo
                # para fallar el logout, pero sí para no fiarse y caer al
                # barrido completo de abajo.
                auth_logger.warning(
                    f"Refresh token no utilizable en el logout de {user.username}"
                )

        revoked = 0
        for outstanding in OutstandingToken.objects.filter(
            user=user, expires_at__gt=timezone.now()
        ):
            _, created = BlacklistedToken.objects.get_or_create(token=outstanding)
            revoked += int(created)
        return revoked


class CookieTokenRefreshView(TokenRefreshView):
    """Renueva el access leyendo el refresh de la cookie HttpOnly (paso 8).

    La `TokenRefreshView` de la librería espera el refresh en el cuerpo y
    devuelve el nuevo access en el cuerpo. Con los tokens en cookies eso ya no
    vale: el navegador no puede leer ni escribir cookies HttpOnly, así que el
    refresh entra por la cookie y los tokens nuevos salen por `Set-Cookie`.

    Se conserva el respaldo por cuerpo para clientes que no sean navegador.

    CSRF: es POST y muta estado —con `ROTATE_REFRESH_TOKENS` cada renovación
    emite un refresh nuevo e invalida el anterior—, y se apoya en una cookie que
    el navegador manda sola, así que exige CSRF como el resto de mutaciones.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        # CSRF explícito (esta vista no pasa por CookieJWTAuthentication).
        # No se usa @csrf_protect: sobre la Request de DRF lee `request.POST`,
        # que con el cuerpo vacío que manda el navegador dispara el parser JSON
        # y devuelve 400. `enforce_csrf` opera sobre la request de Django.
        enforce_csrf(request)

        raw = get_refresh_from_cookie(request)
        if not raw:
            # Respaldo para clientes no-navegador: leer del cuerpo con cuidado.
            # `request.data` sobre un cuerpo vacío levanta ParseError, así que se
            # protege; con la cookie presente (caso del navegador) no se toca.
            try:
                raw = request.data.get('refresh') or request.data.get('refresh_token')
            except Exception:
                raw = None

        if not raw:
            response = JsonResponse({
                'success': False,
                'error': 'Sesión expirada'
            }, status=401)
            return clear_auth_cookies(response)

        serializer = self.get_serializer(data={'refresh': raw})
        try:
            serializer.is_valid(raise_exception=True)
        except (InvalidToken, TokenError):
            # Refresh caducado, ya rotado o manipulado: se limpian las cookies
            # para que el cliente no reintente en bucle con un token muerto.
            response = JsonResponse({
                'success': False,
                'error': 'Sesión expirada'
            }, status=401)
            return clear_auth_cookies(response)

        validated = serializer.validated_data
        response = JsonResponse({'success': True})
        # Con rotación, `validated` trae un 'refresh' nuevo; si no la hubiera,
        # `.get` devuelve None y set_auth_cookies deja la cookie de refresh como
        # está.
        return set_auth_cookies(response, validated['access'], validated.get('refresh'))


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
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
        
    except Exception:
        auth_logger.exception("Error en check_auth_status")
        return JsonResponse({
            'success': False,
            'error': 'Error verificando autenticación'
        }, status=500)
        
@api_view(['GET'])
@permission_classes([AllowAny])
@authentication_classes([])
@ensure_csrf_cookie  # Asegura que la cookie CSRF se establezca
def get_csrf_token(request):
    """Entrega la cookie CSRF y su valor. Es el primer contacto del cliente.

    Bloqueador que arrastraba desde antes (cerraba W015): sin
    `@permission_classes([AllowAny])`, heredaba el `IsAuthenticated` por
    defecto de DRF, así que devolvía 401 a quien aún no tiene sesión —es decir,
    a todo el mundo, porque la base de datos está vacía—. El cliente no podía
    obtener la cookie CSRF antes de autenticarse, y sin ella el login (que va
    con `csrf_protect`) tampoco pasaba. Era un punto muerto en el arranque.

    `@authentication_classes([])` lo desengancha además de
    `CookieJWTAuthentication`: no tiene sentido validar (ni exigir CSRF sobre)
    un token para la petición cuyo único fin es entregar el CSRF. Es GET, así
    que no muta nada.
    """
    try:
        # Obtener el token CSRF
        token = get_token(request)
        
        # Log para debugging
        auth_logger.info(f"CSRF token generado para IP: {get_client_ip(request)}")
        
        return JsonResponse({
            'csrfToken': token,
            'success': True
        })
    except Exception:
        auth_logger.exception("Error generando CSRF token")
        return JsonResponse({
            'error': 'Error generando token CSRF',
            'success': False
        }, status=500)