# myapp/middleware.py - Middlewares de seguridad personalizados

import logging
import json
import time
from datetime import datetime, timedelta
from django.http import JsonResponse, HttpResponseForbidden
from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .models import SecurityEvent, ActivityLog
import ipaddress
from user_agents import parse

# Configurar loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')
auth_logger = logging.getLogger('auth')

User = get_user_model()

class SecurityLoggingMiddleware(MiddlewareMixin):
    """Middleware para registrar eventos de seguridad sospechosos"""
    
    SUSPICIOUS_PATTERNS = [
        'SELECT', 'UNION', 'DROP', 'DELETE', '--', ';',  # SQL Injection
        '<script', 'javascript:', 'eval(', 'alert(',      # XSS
        '../', '..\\', '/etc/passwd', 'wp-admin',         # Path traversal
        'cmd=', 'exec=', 'system=',                       # Command injection
    ]
    
    SENSITIVE_HEADERS = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_USER_AGENT',
        'HTTP_REFERER',
        'HTTP_AUTHORIZATION',
    ]
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        # Obtener información del cliente
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Log de todas las requests a endpoints sensibles
        if self.is_sensitive_endpoint(request.path):
            auth_logger.info(f"Request to sensitive endpoint: {request.path} from IP: {ip_address}")
        
        # Detectar patrones sospechosos
        suspicious_activity = self.detect_suspicious_patterns(request)
        
        if suspicious_activity:
            self.log_security_event(request, suspicious_activity, ip_address, user_agent)
            
            # Bloquear IPs sospechosas
            if self.should_block_ip(ip_address, suspicious_activity):
                return JsonResponse({
                    'error': 'Acceso denegado por actividad sospechosa'
                }, status=403)
        
        return None
    
    def process_response(self, request, response):
        # Log de respuestas de error de autenticación
        if response.status_code in [401, 403]:
            ip_address = self.get_client_ip(request)
            security_logger.warning(
                f"Authentication error {response.status_code} for IP: {ip_address} "
                f"on endpoint: {request.path}"
            )
        
        return response
    
    def get_client_ip(self, request):
        """Obtiene la IP real del cliente considerando proxies"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def is_sensitive_endpoint(self, path):
        """Verifica si el endpoint es sensible"""
        sensitive_endpoints = [
            '/auth/', '/api/passwords/', '/api/files/', 
            '/admin/', '/api/master-key/', '/api/vaults/'
        ]
        return any(path.startswith(endpoint) for endpoint in sensitive_endpoints)
    
    def detect_suspicious_patterns(self, request):
        """Detecta patrones sospechosos en la request"""
        suspicious = []
        
        # Verificar en la URL
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.lower() in request.path.lower():
                suspicious.append(f"Suspicious pattern in URL: {pattern}")
        
        # Verificar en headers
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        if any(bot in user_agent for bot in ['sqlmap', 'nikto', 'nmap', 'burp']):
            suspicious.append("Suspicious user agent detected")
        
        # Verificar parámetros POST/GET
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if pattern.lower() in str(value).lower():
                        suspicious.append(f"Suspicious pattern in POST data: {pattern}")
        
        # Verificar tamaño de request
        if request.content_type and 'json' in request.content_type:
            try:
                if len(request.body) > 1024 * 1024:  # 1MB
                    suspicious.append("Unusually large request body")
            except:
                pass
        
        return suspicious
    
    def log_security_event(self, request, suspicious_activity, ip_address, user_agent):
        """Registra evento de seguridad"""
        user = request.user if hasattr(request, 'user') and request.user.is_authenticated else None
        
        try:
            SecurityEvent.objects.create(
                user=user,
                event_type='suspicious_activity',
                description=f"Suspicious patterns detected: {', '.join(suspicious_activity)}",
                ip_address=ip_address,
                user_agent=user_agent,
                additional_data={
                    'path': request.path,
                    'method': request.method,
                    'patterns': suspicious_activity,
                    'timestamp': datetime.now().isoformat()
                }
            )
        except Exception as e:
            security_logger.error(f"Failed to log security event: {e}")
        
        security_logger.warning(
            f"SUSPICIOUS ACTIVITY - IP: {ip_address}, Path: {request.path}, "
            f"Patterns: {suspicious_activity}, User-Agent: {user_agent[:100]}"
        )
    
    def should_block_ip(self, ip_address, suspicious_activity):
        """Determina si debe bloquear la IP"""
        cache_key = f"suspicious_ip_{ip_address}"
        attempts = cache.get(cache_key, 0)
        
        # Incrementar contador
        cache.set(cache_key, attempts + 1, 3600)  # 1 hora
        
        # Bloquear después de 3 intentos sospechosos
        return attempts >= 3


class SessionSecurityMiddleware(MiddlewareMixin):
    """Middleware adicional para seguridad de sesiones"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        # Verificar integridad de la sesión
        if hasattr(request, 'user') and request.user.is_authenticated:
            # Verificar si la IP cambió (opcional, puede ser problemático con proxies)
            session_ip = request.session.get('ip_address')
            current_ip = self.get_client_ip(request)
            
            if session_ip and session_ip != current_ip:
                # Log de cambio de IP sospechoso
                security_logger.warning(
                    f"IP address changed during session for user {request.user.username}: "
                    f"{session_ip} -> {current_ip}"
                )
                # Opcional: forzar re-autenticación
                # del request.session['_auth_user_id']
            
            # Actualizar IP en sesión
            request.session['ip_address'] = current_ip
            
            # Verificar User-Agent (más estricto)
            session_ua = request.session.get('user_agent')
            current_ua = request.META.get('HTTP_USER_AGENT', '')
            
            if session_ua and session_ua != current_ua:
                security_logger.warning(
                    f"User-Agent changed during session for user {request.user.username}"
                )
                # En aplicaciones críticas como gestores de contraseñas, 
                # podrías forzar re-autenticación aquí
            
            request.session['user_agent'] = current_ua
            
            # Renovar sesión periódicamente para mayor seguridad
            last_activity = request.session.get('last_activity')
            current_time = time.time()
            
            if not last_activity or current_time - last_activity > 1800:  # 30 minutos
                # Renovar ID de sesión para prevenir session fixation
                request.session.cycle_key()
                security_logger.info(f"Session renewed for user {request.user.username}")
            
            request.session['last_activity'] = current_time
        
        return None
    
    def get_client_ip(self, request):
        """Obtiene la IP del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RateLimitMiddleware(MiddlewareMixin):
    """
    Middleware inteligente para rate limiting granular
    Solo aplica límites estrictos donde realmente se necesita
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        # Solo aplicar rate limiting a endpoints específicos
        endpoint_type = self.classify_endpoint(request, request.path)
        
        if endpoint_type == 'auth':
            return self.check_auth_rate_limit(request)
        elif endpoint_type == 'sensitive':
            return self.check_sensitive_rate_limit(request)
        elif endpoint_type == 'upload':
            return self.check_upload_rate_limit(request)
        # Los endpoints 'data' y 'normal' NO tienen rate limiting
        
        return None
    
    def classify_endpoint(self, request, path):
        """Clasifica el endpoint para aplicar rate limiting apropiado"""
        
        # Endpoints de autenticación - MUY RESTRICTIVO
        auth_endpoints = [
            '/auth/login/', '/auth/register/', '/api/token/',
            '/auth/logout/', '/api/master-key/verify/'
        ]
        if any(path.startswith(endpoint) for endpoint in auth_endpoints):
            return 'auth'
        
        # Endpoints sensibles - MODERADAMENTE RESTRICTIVO  
        sensitive_endpoints = [
            '/api/master-key/setup/', '/api/master-key/change/',
            '/api/passwords/', '/api/vaults/', '/api/user-settings/'
        ]
        if any(path.startswith(endpoint) for endpoint in sensitive_endpoints):
            # Solo aplicar límites a operaciones de escritura
            if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                return 'sensitive'
        
        # Endpoints de subida de archivos - MODERADO
        upload_endpoints = ['/api/files/upload/']
        if any(path.startswith(endpoint) for endpoint in upload_endpoints):
            return 'upload'
        
        # Endpoints de datos del cliente - SIN LÍMITES
        data_endpoints = [
            '/api/dashboard/', '/api/accounts/', '/api/unlock-password/',
            '/api/unlock-all-accounts/', '/api/password-generator/',
            '/api/files/', '/api/security/', '/api/csrf/'
        ]
        if any(path.startswith(endpoint) for endpoint in data_endpoints):
            return 'data'  # Sin rate limiting
        
        # Otros endpoints - SIN LÍMITES
        return 'normal'
    
    def check_auth_rate_limit(self, request):
        """Rate limiting ESTRICTO para autenticación - 10 intentos por 5 minutos"""
        ip = self.get_client_ip(request)
        cache_key = f"auth_limit_{ip}"
        
        attempts = cache.get(cache_key, [])
        now = time.time()
        
        # Filtrar intentos de los últimos 5 minutos (300 segundos)
        attempts = [attempt for attempt in attempts if now - attempt < 300]
        
        if len(attempts) >= 10:
            security_logger.warning(f"Auth rate limit exceeded by IP: {ip}")
            return JsonResponse({
                'error': 'Demasiados intentos de autenticación. Espera 5 minutos.',
                'retry_after': 300
            }, status=429)
        
        attempts.append(now)
        cache.set(cache_key, attempts, 600)  # 10 minutos de cache
        
        return None
    
    def check_sensitive_rate_limit(self, request):
        """Rate limiting MODERADO para operaciones sensibles - 50 por hora"""
        identifier = self.get_rate_limit_identifier(request)
        cache_key = f"sensitive_limit_{identifier}"
        
        attempts = cache.get(cache_key, [])
        now = time.time()
        
        # Filtrar intentos de la última hora
        attempts = [attempt for attempt in attempts if now - attempt < 3600]
        
        if len(attempts) >= 50:
            security_logger.warning(f"Sensitive operations rate limit exceeded by {identifier}")
            return JsonResponse({
                'error': 'Demasiadas operaciones sensibles. Espera un momento.',
                'retry_after': 3600
            }, status=429)
        
        attempts.append(now)
        cache.set(cache_key, attempts, 3600)
        
        return None
    
    def check_upload_rate_limit(self, request):
        """Rate limiting para subida de archivos - 20 por hora"""
        identifier = self.get_rate_limit_identifier(request)
        cache_key = f"upload_limit_{identifier}"
        
        attempts = cache.get(cache_key, [])
        now = time.time()
        
        # Filtrar intentos de la última hora
        attempts = [attempt for attempt in attempts if now - attempt < 3600]
        
        if len(attempts) >= 20:
            security_logger.warning(f"Upload rate limit exceeded by {identifier}")
            return JsonResponse({
                'error': 'Demasiadas subidas de archivo. Espera un momento.',
                'retry_after': 3600
            }, status=429)
        
        attempts.append(now)
        cache.set(cache_key, attempts, 3600)
        
        return None
    
    def get_rate_limit_identifier(self, request):
        """Obtiene identificador para rate limiting (user_id o IP)"""
        if hasattr(request, 'user') and request.user.is_authenticated:
            return f"user_{request.user.id}"
        else:
            return f"ip_{self.get_client_ip(request)}"
    
    def get_client_ip(self, request):
        """Obtiene la IP del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class JWTAuthenticationMiddleware(MiddlewareMixin):
    """Middleware para manejar autenticación JWT"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = JWTAuthentication()
        super().__init__(get_response)
    
    def process_request(self, request):
        # Solo procesar requests a endpoints de API que requieren auth
        if not self.requires_jwt_auth(request.path):
            return None
        
        # Intentar autenticación JWT
        try:
            auth_result = self.jwt_auth.authenticate(request)
            if auth_result is not None:
                user, token = auth_result
                request.user = user
                request.jwt_token = token
                
                # Log de autenticación exitosa
                auth_logger.info(f"JWT authentication successful for user: {user.username}")
            else:
                # No hay token JWT, verificar si hay autenticación de sesión
                if not hasattr(request, 'user') or isinstance(request.user, AnonymousUser):
                    return JsonResponse({
                        'error': 'Autenticación requerida'
                    }, status=401)
                    
        except (InvalidToken, TokenError) as e:
            security_logger.warning(f"Invalid JWT token: {e}")
            return JsonResponse({
                'error': 'Token inválido o expirado'
            }, status=401)
        except Exception as e:
            security_logger.error(f"JWT authentication error: {e}")
            return JsonResponse({
                'error': 'Error de autenticación'
            }, status=500)
        
        return None
    
    def requires_jwt_auth(self, path):
        """Determina si el endpoint requiere autenticación JWT"""
        jwt_endpoints = [
            '/api/passwords/',
            '/api/files/',
            '/api/master-key/',
            '/api/user/',
            '/api/activity/',
            '/api/vaults/',
        ]
        return any(path.startswith(endpoint) for endpoint in jwt_endpoints)


class AuditMiddleware(MiddlewareMixin):
    """Middleware para auditoría completa de actividades"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        # Guardar timestamp de inicio
        request._audit_start_time = time.time()
        return None
    
    def process_response(self, request, response):
        # Solo auditar endpoints importantes
        if not self.should_audit(request.path):
            return response
        
        # Calcular duración de la request
        duration = None
        if hasattr(request, '_audit_start_time'):
            duration = time.time() - request._audit_start_time
        
        # Obtener información del usuario
        user = None
        if hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
        
        # Obtener información de la request
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Determinar tipo de actividad
        activity_type = self.determine_activity_type(request.path, request.method, response.status_code)
        
        if activity_type:
            try:
                ActivityLog.objects.create(
                    user=user,
                    activity_type=activity_type,
                    title=self.generate_activity_title(activity_type, request),
                    description=self.generate_activity_description(request, response, duration),
                    severity=self.determine_severity(response.status_code),
                    ip_address=ip_address,
                    user_agent=user_agent[:500] if user_agent else '',
                    related_object_type=self.get_related_object_type(request.path),
                )
                
                # Log adicional para actividades críticas
                if self.is_critical_activity(activity_type, response.status_code):
                    audit_logger.warning(
                        f"CRITICAL ACTIVITY - User: {user.username if user else 'Anonymous'}, "
                        f"Action: {activity_type}, Path: {request.path}, "
                        f"Status: {response.status_code}, IP: {ip_address}"
                    )
                
            except Exception as e:
                audit_logger.error(f"Failed to log activity: {e}")
        
        return response
    
    def should_audit(self, path):
        """Determina si debe auditarse este endpoint"""
        audit_paths = [
            '/auth/', '/api/passwords/', '/api/files/', 
            '/api/master-key/', '/api/vaults/', '/api/user/settings/'
        ]
        return any(path.startswith(audit_path) for audit_path in audit_paths)
    
    def determine_activity_type(self, path, method, status_code):
        """Determina el tipo de actividad basado en la ruta y método"""
        if status_code >= 400:
            return None  # No auditar errores aquí
        
        if '/auth/login/' in path and method == 'POST':
            return 'login'
        elif '/auth/logout/' in path and method == 'POST':
            return 'logout'
        elif '/auth/register/' in path and method == 'POST':
            return 'login'  # Registro exitoso = login automático
        elif '/api/passwords/' in path:
            if method == 'POST':
                return 'password_created'
            elif method == 'PUT' or method == 'PATCH':
                return 'password_updated'
            elif method == 'DELETE':
                return 'password_deleted'
            elif method == 'GET':
                return 'password_viewed'
        elif '/api/files/' in path:
            if method == 'POST':
                return 'file_uploaded'
            elif method == 'GET':
                return 'file_downloaded'
            elif method == 'DELETE':
                return 'file_deleted'
        elif '/api/master-key/' in path and method == 'POST':
            return 'master_key_verified'
        elif '/api/vaults/' in path:
            if method == 'POST':
                return 'vault_created'
            elif method == 'PUT' or method == 'PATCH':
                return 'vault_updated'
            elif method == 'DELETE':
                return 'vault_deleted'
        
        return None
    
    def generate_activity_title(self, activity_type, request):
        """Genera título descriptivo para la actividad"""
        titles = {
            'login': 'Inicio de sesión exitoso',
            'logout': 'Cierre de sesión',
            'password_created': 'Nueva contraseña creada',
            'password_updated': 'Contraseña actualizada',
            'password_deleted': 'Contraseña eliminada',
            'password_viewed': 'Contraseña visualizada',
            'file_uploaded': 'Archivo subido',
            'file_downloaded': 'Archivo descargado',
            'file_deleted': 'Archivo eliminado',
            'master_key_verified': 'Clave maestra verificada',
            'vault_created': 'Vault creado',
            'vault_updated': 'Vault actualizado',
            'vault_deleted': 'Vault eliminado',
        }
        return titles.get(activity_type, f'Actividad: {activity_type}')
    
    def generate_activity_description(self, request, response, duration):
        """Genera descripción detallada de la actividad"""
        description = f"Endpoint: {request.path}, Método: {request.method}"
        
        if duration:
            description += f", Duración: {duration:.2f}s"
        
        if hasattr(request, 'user') and request.user.is_authenticated:
            description += f", Usuario: {request.user.username}"
        
        return description
    
    def determine_severity(self, status_code):
        """Determina la severidad basada en el código de estado"""
        if status_code >= 500:
            return 'error'
        elif status_code >= 400:
            return 'warning'
        elif status_code >= 300:
            return 'info'
        else:
            return 'success'
    
    def get_related_object_type(self, path):
        """Determina el tipo de objeto relacionado"""
        if '/passwords/' in path:
            return 'password'
        elif '/files/' in path:
            return 'file'
        elif '/vaults/' in path:
            return 'vault'
        elif '/auth/' in path:
            return 'auth'
        return None
    
    def is_critical_activity(self, activity_type, status_code):
        """Determina si es una actividad crítica que requiere log especial"""
        critical_activities = [
            'password_deleted', 'file_deleted', 'vault_deleted',
            'master_key_verified', 'login'
        ]
        return activity_type in critical_activities and status_code < 400
    
    def get_client_ip(self, request):
        """Obtiene la IP del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip