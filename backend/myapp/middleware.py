import logging
import time
from datetime import datetime, timedelta
from django.conf import settings
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth.models import AnonymousUser
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from rest_framework.exceptions import PermissionDenied
from .authentication import CookieJWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from .models import SecurityEvent, ActivityLog
import json
import ipaddress
from user_agents import parse
from .session_manager import SessionManager
from .utils.cache_utils import (
    CacheUnavailable,
    lenient_get,
    lenient_set,
    service_unavailable_response,
    strict_get,
    strict_set,
)
from .utils.request_utils import get_client_ip, get_client_ip_with_trust, get_user_agent

# Configurar loggers
security_logger = logging.getLogger('security')
audit_logger = logging.getLogger('audit')
auth_logger = logging.getLogger('auth')

User = get_user_model()

class SecurityLoggingMiddleware(MiddlewareMixin):
    """Detección de escaneo por ruta y método, con umbral de tasa (M12).

    Lo que había antes era una lista de subcadenas —`SELECT`, `UNION`, `DROP`,
    `DELETE`, `--`, `;`, `<script`, `../`…— buscada en la ruta **y en cada valor
    de `request.POST`**, con bloqueo de la IP tras 3 coincidencias. En un gestor
    de contraseñas eso no es un WAF, es una avería:

    - El cuerpo de un POST contiene contraseñas generadas al azar sobre
      `string.punctuation`, que incluye `;` y `-`. **Una contraseña de 20
      caracteres tiene ~74 % de probabilidad de contener al menos un `;`**, y
      basta con cuatro para dejar al usuario fuera durante una hora. El control
      castigaba precisamente las contraseñas buenas.
    - Peor aún, la comparación era `pattern.lower() in path.lower()`, así que el
      patrón `DELETE` casaba con `/passwords/5/delete/`,
      `/api/files/3/delete/`, `/api/vaults/2/delete/` y
      `/api/batch-delete-passwords/`: **borrar cuatro elementos bloqueaba la
      cuenta**. Rutas normales de la aplicación, no ataques.
    - Leer `request.POST` desde un middleware que corre antes que la vista
      consume el flujo de una subida multipart, que es otro de los motivos por
      los que la subida de ficheros no funcionaba.
    - No aportaba defensa: el ORM parametriza las consultas, y quien realmente
      quiera inyectar evita cuatro subcadenas fijas sin despeinarse.

    Lo que hace ahora: mira **sólo la ruta** (nunca el cuerpo ni los valores de
    los parámetros, que es donde viajan los secretos) buscando rutas que esta
    aplicación no sirve en ningún caso, y bloquea únicamente cuando se acumulan
    varias en poco tiempo, que es la firma de un escáner y no la de un usuario.
    """

    # Rutas que ningún cliente legítimo pide jamás aquí. No hay una sola línea
    # de PHP, ASP ni JSP en el proyecto, ni panel de Tomcat, ni Solr: cualquier
    # petición a estas rutas es reconocimiento automatizado.
    #
    # Ojo con la trampa que hace falsos positivos: hay un catch-all
    # (`path('<path:path>', app_view)`) que devuelve **200 con la SPA** para
    # cualquier ruta desconocida, así que no se puede detectar el escaneo
    # contando 404 — nunca los hay. Por eso la detección va por ruta.
    PROBE_PATH_MARKERS = (
        '/wp-admin', '/wp-login', '/wp-content', '/wp-includes', 'xmlrpc.php',
        '/phpmyadmin', '/adminer', '/pma/',
        '/.env', '/.git/', '/.svn/', '/.aws/', '/.ssh/', '/.htaccess',
        '/cgi-bin/', '/vendor/phpunit', '/manager/html',
        '/etc/passwd', '/proc/self/environ',
        '/actuator/', '/solr/', '/jenkins/', '/telescope/',
    )

    PROBE_PATH_SUFFIXES = ('.php', '.asp', '.aspx', '.jsp', '.cgi', '.env')

    # Sólo para registro: el User-Agent lo elige el atacante y cambiarlo es un
    # flag de línea de órdenes. Nunca cuenta para bloquear, porque bloquear por
    # algo que se evade gratis sólo sirve para creerse protegido.
    SCANNER_USER_AGENTS = (
        'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'nuclei',
        'dirbuster', 'gobuster', 'feroxbuster', 'wpscan',
        'acunetix', 'netsparker', 'burpcollaborator',
    )

    PROBE_WINDOW_SECONDS = 600      # ventana en la que se acumulan sondeos
    PROBE_BLOCK_THRESHOLD = 12      # sondeos en esa ventana antes de bloquear
    PROBE_BLOCK_SECONDS = 900       # duración del bloqueo
    EVENT_COOLDOWN_SECONDS = 60     # 1 SecurityEvent por IP y minuto, como mucho

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

    def process_request(self, request):
        ip_address, ip_is_attributable = get_client_ip_with_trust(request)
        user_agent = get_user_agent(request)

        # Log de todas las requests a endpoints sensibles
        if self.is_sensitive_endpoint(request.path):
            auth_logger.info(f"Request to sensitive endpoint: {request.path} from IP: {ip_address}")

        if ip_is_attributable and self._is_blocked(ip_address):
            return JsonResponse({
                'error': 'Acceso denegado por actividad sospechosa'
            }, status=403)

        signals, is_probe = self.detect_suspicious_request(request, user_agent)
        if not signals:
            return None

        hits = self._record_probe(ip_address) if (is_probe and ip_is_attributable) else 0
        self.log_security_event(request, signals, ip_address, user_agent, hits)

        # Sólo se bloquea con IP atribuible (ver `get_client_ip_with_trust`) y
        # con señales de ruta, nunca por User-Agent ni por contenido.
        if hits >= self.PROBE_BLOCK_THRESHOLD:
            self._block(ip_address, hits)
            return JsonResponse({
                'error': 'Acceso denegado por actividad sospechosa'
            }, status=403)

        return None

    def process_response(self, request, response):
        # Log de respuestas de error de autenticación
        if response.status_code in [401, 403]:
            ip_address = get_client_ip(request)
            security_logger.warning(
                f"Authentication error {response.status_code} for IP: {ip_address} "
                f"on endpoint: {request.path}"
            )
        
        return response

    def is_sensitive_endpoint(self, path):
        """Verifica si el endpoint es sensible"""
        sensitive_endpoints = [
            '/auth/', '/api/passwords/', '/api/files/', 
            '/admin/', '/api/master-key/', '/api/vaults/'
        ]
        return any(path.startswith(endpoint) for endpoint in sensitive_endpoints)
    
    def detect_suspicious_request(self, request, user_agent):
        """Devuelve `(señales, es_sondeo)` mirando ruta, método y User-Agent.

        `es_sondeo` distingue lo que cuenta para el umbral de bloqueo (señales
        de ruta, que el cliente sólo produce pidiendo algo que aquí no existe)
        de lo que sólo se registra (User-Agent).

        Nunca se inspecciona el cuerpo ni los valores de los parámetros: en esta
        aplicación eso es material secreto, y mirarlo fue el origen de M12.
        """
        signals = []
        is_probe = False

        path = request.path.lower()
        query = request.META.get('QUERY_STRING', '').lower()

        if any(marker in path for marker in self.PROBE_PATH_MARKERS):
            signals.append('probe_path')
            is_probe = True
        elif path.endswith(self.PROBE_PATH_SUFFIXES):
            # La aplicación no sirve ni una sola ruta con estas extensiones.
            signals.append('probe_extension')
            is_probe = True

        # Travesía de directorios y byte nulo. nginx normaliza la mayoría de los
        # `..` antes de reenviar, así que esto cubre sobre todo el acceso
        # directo a gunicorn; no hay ruta legítima que los contenga.
        if '..' in path or '..' in query:
            signals.append('path_traversal')
            is_probe = True
        if '\x00' in path or '%00' in query:
            signals.append('null_byte')
            is_probe = True

        # Escritura sobre rutas que sólo aceptan lectura: método incoherente con
        # la ruta. Señal de que alguien está probando verbos a mano.
        if request.method in ('PUT', 'PATCH', 'TRACE', 'CONNECT') and path.startswith('/api/'):
            signals.append(f'unexpected_method:{request.method}')
            is_probe = True

        ua = user_agent.lower()
        if any(scanner in ua for scanner in self.SCANNER_USER_AGENTS):
            signals.append('scanner_user_agent')   # sólo registro, no bloquea

        return signals, is_probe

    def log_security_event(self, request, suspicious_activity, ip_address, user_agent, hits=0):
        """Registra evento de seguridad.

        Se limita a uno por IP y minuto: sin ese freno, un escáner que lanza
        miles de peticiones convierte la propia tabla de auditoría en el
        vector de denegación de servicio (una inserción por petición).
        """
        user = request.user if hasattr(request, 'user') and request.user.is_authenticated else None

        security_logger.warning(
            f"SUSPICIOUS ACTIVITY - IP: {ip_address}, Path: {request.path}, "
            f"Method: {request.method}, Signals: {suspicious_activity}, "
            f"Hits: {hits}, User-Agent: {user_agent[:100]}"
        )

        cooldown_key = f"suspicious_event_logged_{ip_address}"
        if lenient_get(cooldown_key):
            return
        lenient_set(cooldown_key, True, self.EVENT_COOLDOWN_SECONDS)

        try:
            SecurityEvent.objects.create(
                user=user,
                event_type='suspicious_activity',
                description=f"Suspicious request signals: {', '.join(suspicious_activity)}",
                ip_address=ip_address,
                user_agent=user_agent,
                additional_data={
                    'path': request.path,
                    'method': request.method,
                    'signals': suspicious_activity,
                    'hits_in_window': hits,
                    'timestamp': datetime.now().isoformat()
                }
            )
        except Exception as e:
            security_logger.error(f"Failed to log security event: {e}")

    # ------------------------------------------------------------------
    # Umbral de tasa y bloqueo
    #
    # Política de caché: LENIENT, decidida en el paso 19 (M6). Este middleware
    # es un control de DETECCIÓN, no de autorización: si Redis cae no se puede
    # contar sondeos, pero fallar cerrado aquí significaría responder 403 a todo
    # el mundo, o sea convertir una avería de Redis en una caída total del
    # servicio provocable desde fuera. Se deja de bloquear escáneres y se grita
    # en los logs. El fail-closed se aplica donde la caché sí autoriza:
    # `RateLimitMiddleware` y el bloqueo de cuenta del login.
    # ------------------------------------------------------------------

    def _is_blocked(self, ip_address):
        return bool(lenient_get(f"probe_block_{ip_address}"))

    def _record_probe(self, ip_address):
        """Anota un sondeo y devuelve cuántos lleva esta IP en la ventana."""
        cache_key = f"probe_hits_{ip_address}"
        now = time.time()
        hits = [t for t in lenient_get(cache_key, []) if now - t < self.PROBE_WINDOW_SECONDS]
        hits.append(now)
        if not lenient_set(cache_key, hits, self.PROBE_WINDOW_SECONDS):
            # Sin poder guardar el contador no hay umbral que valga: se informa
            # de 0 para no bloquear a partir de una cuenta que no persiste.
            return 0
        return len(hits)

    def _block(self, ip_address, hits):
        security_logger.warning(
            "IP bloqueada por escaneo: %s (%d sondeos en %d s)",
            ip_address, hits, self.PROBE_WINDOW_SECONDS,
        )
        lenient_set(f"probe_block_{ip_address}", True, self.PROBE_BLOCK_SECONDS)


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
            current_ip = get_client_ip(request)
            
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

        try:
            if endpoint_type == 'auth':
                return self.check_auth_rate_limit(request)
            elif endpoint_type == 'sensitive':
                return self.check_sensitive_rate_limit(request)
            elif endpoint_type == 'upload':
                return self.check_upload_rate_limit(request)
        except CacheUnavailable:
            # FAIL-CLOSED (M6). Este middleware es lo único que separa el login
            # y la clave maestra de la fuerza bruta ilimitada; si la caché no
            # responde no hay forma de saber cuántos intentos lleva quien
            # llama, y dejar pasar sería exactamente el comportamiento que este
            # paso viene a eliminar. Sólo afecta a las rutas clasificadas como
            # auth/sensitive/upload: el resto de la aplicación sigue en pie.
            security_logger.error(
                "Rate limiting no disponible (caché caída): denegando %s %s",
                request.method, request.path,
            )
            return service_unavailable_response()

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
        
        # Endpoints de subida de archivos - MODERADO
        #
        # Va ANTES que el bloque 'sensitive' porque '/api/files/' entró en esa
        # lista: si se comprobase después, la subida quedaría clasificada como
        # sensible y perdería su límite propio.
        upload_endpoints = ['/api/files/upload/']
        if any(path.startswith(endpoint) for endpoint in upload_endpoints):
            return 'upload'

        # Endpoints sensibles - MODERADAMENTE RESTRICTIVO
        #
        # A3: aquí está TODA ruta que valide la contraseña maestra. Antes sólo
        # se cubría '/api/master-key/verify/' y las demás caían en 'data' o
        # 'normal', o sea sin límite: bastaba con atacar '/api/unlock-password/'
        # en lugar de '/api/master-key/verify/' para tener fuerza bruta
        # ilimitada. El filtro por método deja fuera las lecturas ('/api/files/'
        # y '/api/passwords/unvaulted/' son GET), que no verifican nada.
        sensitive_endpoints = [
            '/api/master-key/setup/', '/api/master-key/change/',
            '/api/passwords/',              # add, delete y update (movidas aquí)
            '/api/vaults/', '/api/user-settings/',
            '/api/batch-delete-passwords/', # verifica la maestra
            '/api/batch-move-passwords/',
            '/api/files/',                  # descarga, borrado y borrado masivo
            '/api/security/',               # check-breach, hoy suspendido en 501
        ]
        if any(path.startswith(endpoint) for endpoint in sensitive_endpoints):
            # Solo aplicar límites a operaciones de escritura
            if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                return 'sensitive'

        # Endpoints de datos del cliente - SIN LÍMITES
        data_endpoints = [
            '/api/dashboard/', '/api/accounts/',
            '/api/password-generator/', '/api/csrf/'
        ]
        if any(path.startswith(endpoint) for endpoint in data_endpoints):
            return 'data'  # Sin rate limiting
        
        # Otros endpoints - SIN LÍMITES
        return 'normal'
    
    def check_auth_rate_limit(self, request):
        """Rate limiting ESTRICTO para autenticación - 10 intentos por 5 minutos"""
        ip = get_client_ip(request)
        cache_key = f"auth_limit_{ip}"
        
        attempts = strict_get(cache_key, [])
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
        strict_set(cache_key, attempts, 600)  # 10 minutos de cache
        
        return None
    
    def check_sensitive_rate_limit(self, request):
        """Rate limiting MODERADO para operaciones sensibles - 70 por hora.

        Subido de 50 a 70 al entrar en este cubo las descargas de fichero y los
        desbloqueos de contraseña (A3): a diferencia del guardián de la clave
        maestra, este contador cuenta **operaciones, no fallos**, así que el
        techo lo gasta también quien trabaja normal. 70/h sigue estando muy por
        debajo de lo que necesita un ataque y por encima de cualquier sesión de
        uso real.
        """
        identifier = self.get_rate_limit_identifier(request)
        cache_key = f"sensitive_limit_{identifier}"

        attempts = strict_get(cache_key, [])
        now = time.time()

        # Filtrar intentos de la última hora
        attempts = [attempt for attempt in attempts if now - attempt < 3600]

        if len(attempts) >= 70:
            security_logger.warning(f"Sensitive operations rate limit exceeded by {identifier}")
            return JsonResponse({
                'error': 'Demasiadas operaciones sensibles. Espera un momento.',
                'retry_after': 3600
            }, status=429)
        
        attempts.append(now)
        strict_set(cache_key, attempts, 3600)
        
        return None
    
    def check_upload_rate_limit(self, request):
        """Rate limiting para subida de archivos - 20 por hora"""
        identifier = self.get_rate_limit_identifier(request)
        cache_key = f"upload_limit_{identifier}"
        
        attempts = strict_get(cache_key, [])
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
        strict_set(cache_key, attempts, 3600)
        
        return None
    
    def get_rate_limit_identifier(self, request):
        """Obtiene identificador para rate limiting (user_id o IP)"""
        if hasattr(request, 'user') and request.user.is_authenticated:
            return f"user_{request.user.id}"
        else:
            return f"ip_{get_client_ip(request)}"


class JWTAuthenticationMiddleware(MiddlewareMixin):
    """Middleware para manejar autenticación JWT"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_auth = CookieJWTAuthentication()
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
                    
        except PermissionDenied as e:
            # CookieJWTAuthentication exige CSRF cuando el token viene de la
            # cookie (paso 8). Sin este `except`, la denegación caería en el
            # genérico de abajo y saldría como 500 opaco en vez de 403, además
            # de fuera de los logs de seguridad. Mismo criterio que en las vistas.
            security_logger.warning(f"CSRF/permiso denegado en JWT middleware: {e}")
            return JsonResponse({
                'error': 'Acceso denegado'
            }, status=403)
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
        
        # Obtener información del usuario - CORREGIDO
        user = None
        if hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
        
        # Si no hay usuario autenticado, no auditar
        if user is None:
            return response
        
        # Obtener información de la request
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Determinar tipo de actividad
        activity_type = self.determine_activity_type(request.path, request.method, response.status_code)
        
        if activity_type:
            try:
                ActivityLog.objects.create(
                    user=user,  # Ahora garantizamos que user no es None
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
                        f"CRITICAL ACTIVITY - User: {user.username}, "
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



class EnhancedSessionTrackingMiddleware(MiddlewareMixin):
    """Middleware mejorado para rastrear y gestionar sesiones avanzadas"""
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.session_manager = SessionManager()
        
        # Endpoints que requieren validación de sesión estricta
        self.strict_validation_endpoints = [
            '/api/master-key/',
            '/api/passwords/',
            '/api/vaults/',
            '/api/files/delete',
            '/api/sessions/terminate'
        ]
        
        # Endpoints que actualizan actividad de sesión
        self.activity_tracking_endpoints = [
            '/api/passwords/',
            '/api/files/',
            '/api/vaults/',
            '/api/master-key/',
            '/api/sessions/'
        ]
    
    def process_request(self, request):
        # Solo procesar para usuarios autenticados
        if not hasattr(request, 'user') or isinstance(request.user, AnonymousUser):
            return None
        
        # Obtener session_id desde múltiples fuentes
        session_id = self._extract_session_id(request)
        
        if session_id:
            # Obtener datos de la sesión
            session_data = self.session_manager.get_session(session_id)
            
            if session_data and self.session_manager.is_session_valid(session_data):
                # Validación de seguridad para endpoints sensibles
                if self._requires_strict_validation(request.path):
                    security_validation = self.session_manager.validate_session_security(session_id, request)
                    
                    if not security_validation['valid']:
                        # Registrar evento de seguridad
                        SecurityEvent.objects.create(
                            user=request.user,
                            event_type='session_security_failure',
                            description=f'Falló validación de seguridad en {request.path}',
                            ip_address=get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            additional_data={
                                'session_id': session_id,
                                'validation_issues': security_validation.get('issues', []),
                                'endpoint': request.path,
                                'method': request.method
                            }
                        )
                        
                        # Si la sesión está comprometida, denegar acceso
                        if security_validation.get('action_required', False):
                            return JsonResponse({
                                'error': 'Sesión comprometida. Por favor, inicia sesión nuevamente.',
                                'session_compromised': True
                            }, status=401)
                
                # Actualizar actividad de la sesión
                if self._should_track_activity(request.path):
                    activity_type = self._determine_activity_type(request.path, request.method)
                    self.session_manager.update_session_activity(session_id, activity_type)
                
                # Agregar datos de sesión al request
                request.session_data = session_data
                request.session_id = session_id
                
                # Verificar si necesita renovación de seguridad
                self._check_security_renewal(request, session_data)
                
            else:
                # Sesión inválida, limpiar
                if session_data:  # Si existe pero no es válida, limpiar
                    self.session_manager.terminate_session(session_id)
                
                request.session_data = None
                request.session_id = None
                
                # Para endpoints que requieren sesión válida, denegar acceso
                if self._requires_valid_session(request.path):
                    return JsonResponse({
                        'error': 'Sesión expirada. Por favor, inicia sesión nuevamente.',
                        'session_expired': True
                    }, status=401)
        else:
            request.session_data = None
            request.session_id = None
        
        return None
    
    def process_response(self, request, response):
        # Registrar métricas de sesión si es necesario
        if (hasattr(request, 'session_id') and request.session_id and 
            hasattr(request, 'user') and not isinstance(request.user, AnonymousUser)):
            
            # Log de actividad para endpoints importantes
            if self._should_log_endpoint_access(request.path, response.status_code):
                self._log_endpoint_access(request, response)
        
        return response
    
    def _extract_session_id(self, request):
        """Extrae session_id de múltiples fuentes con prioridades"""
        # Prioridad 1: Header personalizado (para APIs)
        session_id = request.META.get('HTTP_X_SESSION_ID')
        
        # Prioridad 2: Header Authorization con Bearer token custom
        if not session_id:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header.startswith('Session '):
                session_id = auth_header[8:]  # Remover 'Session '
        
        # Prioridad 3: Cookie personalizada
        if not session_id:
            session_id = request.COOKIES.get('session_id')
        
        # Prioridad 4: Sesión de Django (fallback)
        if not session_id and hasattr(request, 'session'):
            session_id = request.session.get('custom_session_id')
        
        return session_id
    
    def _requires_strict_validation(self, path):
        """Verifica si el endpoint requiere validación estricta de sesión"""
        return any(path.startswith(endpoint) for endpoint in self.strict_validation_endpoints)
    
    def _requires_valid_session(self, path):
        """Verifica si el endpoint requiere una sesión válida obligatoriamente"""
        protected_endpoints = [
            '/api/sessions/',
            '/api/master-key/',
            '/api/passwords/',
            '/api/vaults/',
            '/api/files/',
            '/api/user-settings/'
        ]
        return any(path.startswith(endpoint) for endpoint in protected_endpoints)
    
    def _should_track_activity(self, path):
        """Verifica si debe rastrear actividad para este endpoint"""
        return any(path.startswith(endpoint) for endpoint in self.activity_tracking_endpoints)
    
    def _determine_activity_type(self, path, method):
        """Determina el tipo de actividad basado en el endpoint y método"""
        if '/passwords/' in path:
            if method == 'POST':
                return 'password_create'
            elif method in ['PUT', 'PATCH']:
                return 'password_update'
            elif method == 'DELETE':
                return 'password_delete'
            else:
                return 'password_access'
        elif '/files/' in path:
            if method == 'POST':
                return 'file_upload'
            elif method == 'DELETE':
                return 'file_delete'
            else:
                return 'file_access'
        elif '/vaults/' in path:
            if method == 'POST':
                return 'vault_create'
            elif method in ['PUT', 'PATCH']:
                return 'vault_update'
            elif method == 'DELETE':
                return 'vault_delete'
            else:
                return 'vault_access'
        elif '/sessions/' in path:
            return 'session_management'
        elif '/master-key/' in path:
            return 'master_key_operation'
        else:
            return 'general_api'
    
    def _check_security_renewal(self, request, session_data):
        """Verifica si la sesión necesita renovación de seguridad"""
        last_security_check = session_data.get('last_security_check')
        
        if last_security_check:
            last_check = datetime.fromisoformat(last_security_check.replace('Z', '+00:00'))
            time_since_check = datetime.now() - last_check
            
            # Renovar verificación cada 30 minutos para operaciones sensibles
            if (time_since_check.total_seconds() > 1800 and 
                self._requires_strict_validation(request.path)):
                
                # Actualizar timestamp de verificación
                session_data['last_security_check'] = datetime.now().isoformat()
                session_key = f"{self.session_manager.session_prefix}{request.session_id}"

                lenient_set(
                    session_key,
                    json.dumps(session_data, default=str),
                    self.session_manager.session_timeout,
                )
    
    def _should_log_endpoint_access(self, path, status_code):
        """Determina si debe loguear el acceso a este endpoint"""
        # Loguear accesos a endpoints sensibles o errores
        sensitive_endpoints = [
            '/api/master-key/',
            '/api/passwords/delete',
            '/api/vaults/delete',
            '/api/files/delete',
            '/api/sessions/terminate'
        ]
        
        return (any(path.startswith(endpoint) for endpoint in sensitive_endpoints) or 
                status_code >= 400)
    
    def _log_endpoint_access(self, request, response):
        """Registra acceso a endpoint para auditoría"""
        try:
            from .models import ActivityLog
            
            # Determinar severidad basada en el status code
            if response.status_code >= 500:
                severity = 'error'
            elif response.status_code >= 400:
                severity = 'warning'
            elif response.status_code >= 300:
                severity = 'info'
            else:
                severity = 'success'
            
            # Crear descripción del endpoint
            endpoint_description = f"{request.method} {request.path}"
            if hasattr(request, 'session_data') and request.session_data:
                device_info = request.session_data.get('device_info', {})
                endpoint_description += f" desde {device_info.get('browser', 'Unknown')}"
            
            ActivityLog.objects.create(
                user=request.user,
                activity_type='endpoint_access',
                title=f'Acceso a {request.path}',
                description=endpoint_description,
                severity=severity,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                additional_data={
                    'session_id': getattr(request, 'session_id', None),
                    'method': request.method,
                    'status_code': response.status_code,
                    'endpoint': request.path,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            security_logger.error(f"Error logging endpoint access: {e}")


class SessionCreationMiddleware(MiddlewareMixin):
    """Middleware para crear sesiones automáticamente después del login"""
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.session_manager = SessionManager()
    
    def process_response(self, request, response):
        # Crear sesión después de login exitoso
        if (hasattr(request, 'user') and 
            not isinstance(request.user, AnonymousUser) and
            request.path == '/auth/login/' and 
            response.status_code == 200 and
            not hasattr(request, 'session_id')):
            
            try:
                # Extraer método de login del response
                import json
                response_data = json.loads(response.content)
                
                if response_data.get('success', False):
                    # Crear nueva sesión
                    session_result = self.session_manager.create_session(
                        request.user,
                        request,
                        login_method='password'
                    )

                    # El session_id NO viaja en el cuerpo de la respuesta.
                    #
                    # Antes se copiaba aquí (junto con expires_at y el análisis de
                    # seguridad) y acto seguido se fijaba como cookie `httponly=True`:
                    # el cuerpo del login lo lee el JavaScript, así que publicarlo ahí
                    # anulaba el HttpOnly de la cookie de tres líneas más abajo. Un XSS
                    # no necesitaba tocar la cookie, le bastaba con leer la respuesta.
                    #
                    # No autorizaba nada por sí solo —SessionValidationMiddleware sale
                    # antes si el usuario no viene ya autenticado por JWT—, pero fijar
                    # HttpOnly sobre un valor que se publica al lado es contradictorio.
                    #
                    # Nadie lo necesita en el cuerpo: el navegador manda la cookie sola
                    # (prioridad 3 de `_extract_session_id`), `AuthResponse` del cliente
                    # sólo declara {success, error?, user?}, y la pantalla de seguridad
                    # obtiene las sesiones de `/api/sessions/list/`.

                    # Establecer cookie de sesión
                    response.set_cookie(
                        'session_id',
                        session_result['session_id'],
                        max_age=self.session_manager.session_timeout,
                        httponly=True,
                        secure=settings.SESSION_COOKIE_SECURE,
                        samesite='Lax'
                    )
                    
                    security_logger.info(f"Session created automatically for user {request.user.username}")
                    
            except Exception as e:
                security_logger.error(f"Error creating session automatically: {e}")
        
        return response


class SessionCleanupMiddleware(MiddlewareMixin):
    """Middleware para limpieza periódica de sesiones (solo en algunos requests)"""
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.session_manager = SessionManager()
        self.cleanup_probability = 0.001  # 0.1% de probabilidad por request
    
    def process_request(self, request):
        # Ejecutar limpieza ocasionalmente para no impactar performance
        import random
        if random.random() < self.cleanup_probability:
            try:
                # Ejecutar en thread separado para no bloquear el request
                import threading
                cleanup_thread = threading.Thread(
                    target=self.session_manager.cleanup_all_expired_sessions
                )
                cleanup_thread.daemon = True
                cleanup_thread.start()
            except Exception as e:
                security_logger.error(f"Error in background session cleanup: {e}")
        
        return None
