# session_manager.py - Versión mejorada
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from django.core.cache import cache
from django.contrib.auth.models import User
from django.utils import timezone
from user_agents import parse
import hashlib
import logging
from django.conf import settings

logger = logging.getLogger('auth')

class SessionManager:
    """Gestor avanzado de sesiones con Redis - Versión mejorada"""
    
    def __init__(self):
        self.session_prefix = "user_session:"
        self.active_sessions_prefix = "active_sessions:"
        self.device_fingerprint_prefix = "device_fp:"
        self.session_activity_prefix = "session_activity:"
        self.user_session_stats_prefix = "user_stats:"
        
        # Configuraciones flexibles
        self.session_timeout = getattr(settings, 'SESSION_TIMEOUT', 3600 * 12)  # 12 horas
        self.max_sessions_per_user = getattr(settings, 'MAX_SESSIONS_PER_USER', 5)
        self.session_renewal_threshold = getattr(settings, 'SESSION_RENEWAL_THRESHOLD', 1800)  # 30 min
        
        # Configuración de alertas de seguridad
        self.security_alert_enabled = True
        
    def create_session(self, user: User, request, login_method='standard') -> Dict:
        """Crea una nueva sesión con análisis de seguridad mejorado"""
        session_id = str(uuid.uuid4())
        
        # Extraer información del dispositivo
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        parsed_ua = parse(user_agent)
        ip_address = self.get_client_ip(request)
        
        # Crear fingerprint del dispositivo
        device_fingerprint = self.create_device_fingerprint(user_agent, ip_address)
        
        # Información de geolocalización (simulada - implementar con servicio real)
        location_info = self.get_location_info(ip_address)
        
        session_data = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'session_id': session_id,
            'created_at': timezone.now().isoformat(),
            'last_activity': timezone.now().isoformat(),
            'expires_at': (timezone.now() + timedelta(seconds=self.session_timeout)).isoformat(),
            'ip_address': ip_address,
            'device_fingerprint': device_fingerprint,
            'device_info': {
                'browser': f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}",
                'os': f"{parsed_ua.os.family} {parsed_ua.os.version_string}",
                'device': parsed_ua.device.family,
                'is_mobile': parsed_ua.is_mobile,
                'is_tablet': parsed_ua.is_tablet,
                'is_pc': parsed_ua.is_pc,
                'user_agent': user_agent[:200]  # Truncado para almacenamiento
            },
            'location': location_info,
            'is_active': True,
            'login_method': login_method,
            'security_score': 100,  # Score inicial
            'activities_count': 0,
            'last_ip_check': timezone.now().isoformat(),
            'flags': []  # Banderas de seguridad
        }
        
        # Análisis de seguridad antes de crear la sesión
        security_analysis = self.analyze_session_security(user.id, session_data)
        session_data['security_analysis'] = security_analysis
        
        # Aplicar políticas de sesión
        self._apply_session_policies(user.id, session_data)
        
        # Guardar la sesión en Redis
        session_key = f"{self.session_prefix}{session_id}"
        cache.set(session_key, json.dumps(session_data, default=str), timeout=self.session_timeout)
        
        # Agregar a la lista de sesiones activas
        self.add_to_active_sessions(user.id, session_id)
        
        # Limpiar sesiones expiradas
        self.cleanup_expired_sessions(user.id)
        
        # Log con información adicional
        logger.info(
            f"New session created - User: {user.username}, ID: {session_id}, "
            f"IP: {ip_address}, Device: {session_data['device_info']['browser']}, "
            f"Security Score: {session_data['security_score']}"
        )
        
        return {
            'session_id': session_id,
            'security_analysis': security_analysis,
            'expires_at': session_data['expires_at']
        }
    
    def analyze_session_security(self, user_id: int, new_session_data: Dict) -> Dict:
        """Análisis de seguridad mejorado con más métricas"""
        existing_sessions = self.get_user_sessions(user_id)
        alerts = []
        risk_factors = []
        
        # 1. Verificar múltiples ubicaciones geográficas
        locations = set()
        for session in existing_sessions:
            location = session.get('location', {})
            if location and location.get('country'):
                locations.add(location['country'])
        
        new_location = new_session_data.get('location', {})
        if new_location.get('country'):
            if len(locations) > 0 and new_location['country'] not in locations:
                alerts.append({
                    'type': 'geographic_anomaly',
                    'message': f'Nuevo acceso desde {new_location["country"]}',
                    'severity': 'medium',
                    'risk_score': 30
                })
                risk_factors.append('geographic_change')
        
        # 2. Verificar cambio de dispositivo
        device_fingerprints = set()
        for session in existing_sessions:
            if session.get('device_fingerprint'):
                device_fingerprints.add(session['device_fingerprint'])
        
        if (len(device_fingerprints) > 0 and 
            new_session_data['device_fingerprint'] not in device_fingerprints):
            alerts.append({
                'type': 'new_device',
                'message': f'Nuevo dispositivo: {new_session_data["device_info"]["os"]} - {new_session_data["device_info"]["browser"]}',
                'severity': 'low',
                'risk_score': 10
            })
            risk_factors.append('new_device')
        
        # 3. Verificar múltiples sesiones simultáneas
        active_count = len(existing_sessions)
        if active_count >= 3:
            alerts.append({
                'type': 'multiple_sessions',
                'message': f'{active_count} sesiones activas simultáneamente',
                'severity': 'medium',
                'risk_score': 20
            })
            risk_factors.append('multiple_sessions')
        
        # 4. Verificar patrones de tiempo sospechosos
        if existing_sessions:
            last_session = max(existing_sessions, key=lambda x: x['created_at'])
            last_login = datetime.fromisoformat(last_session['created_at'].replace('Z', '+00:00'))
            time_since_last = timezone.now() - last_login
            
            # Login muy rápido después del anterior (posible ataque)
            if time_since_last.total_seconds() < 30:
                alerts.append({
                    'type': 'rapid_login',
                    'message': 'Login muy rápido después de la sesión anterior',
                    'severity': 'high',
                    'risk_score': 50
                })
                risk_factors.append('rapid_login')
        
        # 5. Verificar horarios inusuales (si hay historial)
        current_hour = timezone.now().hour
        if not (9 <= current_hour <= 23):  # Fuera del horario típico
            alerts.append({
                'type': 'unusual_time',
                'message': f'Login en horario inusual: {current_hour:02d}:xx',
                'severity': 'low',
                'risk_score': 5
            })
            risk_factors.append('unusual_time')
        
        # Calcular score de riesgo total
        total_risk_score = sum(alert['risk_score'] for alert in alerts)
        security_score = max(0, 100 - total_risk_score)
        
        return {
            'is_suspicious': len(alerts) > 0,
            'alerts': alerts,
            'risk_factors': risk_factors,
            'risk_score': total_risk_score,
            'security_score': security_score,
            'recommendation': self._get_security_recommendation(total_risk_score)
        }
    
    def _get_security_recommendation(self, risk_score: int) -> str:
        """Obtiene recomendación de seguridad basada en el score de riesgo"""
        if risk_score >= 50:
            return 'high_risk'  # Requerir 2FA adicional
        elif risk_score >= 20:
            return 'medium_risk'  # Monitorear de cerca
        else:
            return 'low_risk'  # Sesión normal
    
    def _apply_session_policies(self, user_id: int, session_data: Dict):
        """Aplica políticas de sesión como límites y limpieza"""
        # Obtener sesiones actuales
        existing_sessions = self.get_user_sessions(user_id)
        
        # Si se excede el límite, eliminar las más antiguas
        if len(existing_sessions) >= self.max_sessions_per_user:
            sessions_to_remove = len(existing_sessions) - self.max_sessions_per_user + 1
            oldest_sessions = sorted(existing_sessions, key=lambda x: x['created_at'])[:sessions_to_remove]
            
            for old_session in oldest_sessions:
                self.terminate_session(old_session['session_id'], user_id)
            
            logger.info(f"Removed {sessions_to_remove} old sessions for user {user_id}")
    
    def update_session_activity(self, session_id: str, activity_type: str = 'general') -> bool:
        """Actualiza actividad de sesión con tipo de actividad"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        now = timezone.now()
        session['last_activity'] = now.isoformat()
        session['expires_at'] = (now + timedelta(seconds=self.session_timeout)).isoformat()
        session['activities_count'] = session.get('activities_count', 0) + 1
        
        # Renovar sesión si es necesario (prevenir session fixation)
        last_renewal = session.get('last_renewal', session['created_at'])
        if isinstance(last_renewal, str):
            last_renewal = datetime.fromisoformat(last_renewal.replace('Z', '+00:00'))
        
        time_since_renewal = now - last_renewal
        if time_since_renewal.total_seconds() > self.session_renewal_threshold:
            session['last_renewal'] = now.isoformat()
            logger.info(f"Session security renewal for session {session_id}")
        
        # Guardar actividad específica
        self._log_session_activity(session_id, activity_type)
        
        session_key = f"{self.session_prefix}{session_id}"
        cache.set(session_key, json.dumps(session, default=str), timeout=self.session_timeout)
        
        return True
    
    def _log_session_activity(self, session_id: str, activity_type: str):
        """Log de actividades específicas de la sesión"""
        activity_key = f"{self.session_activity_prefix}{session_id}"
        activities = cache.get(activity_key, [])
        
        activities.append({
            'type': activity_type,
            'timestamp': timezone.now().isoformat()
        })
        
        # Mantener solo las últimas 50 actividades
        if len(activities) > 50:
            activities = activities[-50:]
        
        cache.set(activity_key, activities, timeout=self.session_timeout)
    
    def get_session_activities(self, session_id: str) -> List[Dict]:
        """Obtiene las actividades de una sesión específica"""
        activity_key = f"{self.session_activity_prefix}{session_id}"
        return cache.get(activity_key, [])
    
    def validate_session_security(self, session_id: str, request) -> Dict:
        """Valida la seguridad de una sesión en cada request importante"""
        session = self.get_session(session_id)
        if not session:
            return {'valid': False, 'reason': 'session_not_found'}
        
        current_ip = self.get_client_ip(request)
        current_ua = request.META.get('HTTP_USER_AGENT', '')
        
        security_issues = []
        
        # 1. Verificar IP (configurable - puede ser problemático con proxies)
        if hasattr(settings, 'STRICT_IP_CHECKING') and settings.STRICT_IP_CHECKING:
            if session['ip_address'] != current_ip:
                security_issues.append('ip_changed')
        
        # 2. Verificar User-Agent cambio significativo
        stored_ua = session['device_info'].get('user_agent', '')
        if stored_ua and self._significant_ua_change(stored_ua, current_ua):
            security_issues.append('user_agent_changed')
        
        # 3. Verificar si la sesión ha sido comprometida
        if 'compromised' in session.get('flags', []):
            security_issues.append('session_compromised')
        
        # 4. Verificar tiempo de inactividad extremo
        last_activity = datetime.fromisoformat(session['last_activity'].replace('Z', '+00:00'))
        inactive_time = timezone.now() - last_activity
        if inactive_time.total_seconds() > (self.session_timeout * 0.9):  # 90% del timeout
            security_issues.append('session_near_expiry')
        
        if security_issues:
            logger.warning(f"Session security issues for {session_id}: {security_issues}")
            return {
                'valid': len(security_issues) == 0 or 'session_near_expiry' in security_issues,
                'issues': security_issues,
                'action_required': 'session_compromised' in security_issues
            }
        
        return {'valid': True, 'issues': []}
    
    def _significant_ua_change(self, old_ua: str, new_ua: str) -> bool:
        """Detecta cambios significativos en User-Agent"""
        if not old_ua or not new_ua:
            return False
        
        old_parsed = parse(old_ua)
        new_parsed = parse(new_ua)
        
        # Cambio de browser o OS es significativo
        return (old_parsed.browser.family != new_parsed.browser.family or
                old_parsed.os.family != new_parsed.os.family)
    
    def flag_session_as_compromised(self, session_id: str, reason: str = None):
        """Marca una sesión como comprometida"""
        session = self.get_session(session_id)
        if session:
            flags = session.get('flags', [])
            if 'compromised' not in flags:
                flags.append('compromised')
            
            session['flags'] = flags
            session['compromise_reason'] = reason or 'manual_flag'
            session['compromise_time'] = timezone.now().isoformat()
            
            session_key = f"{self.session_prefix}{session_id}"
            cache.set(session_key, json.dumps(session, default=str), timeout=self.session_timeout)
            
            logger.critical(f"Session {session_id} flagged as compromised: {reason}")
    
    def get_user_sessions_detailed(self, user_id: int) -> Dict:
        """Obtiene sesiones con información detallada incluyendo actividades"""
        sessions = self.get_user_sessions(user_id)
        
        for session in sessions:
            # Agregar actividades recientes
            session['recent_activities'] = self.get_session_activities(session['session_id'])[-10:]
            
            # Calcular métricas adicionales
            created_at = datetime.fromisoformat(session['created_at'].replace('Z', '+00:00'))
            last_activity = datetime.fromisoformat(session['last_activity'].replace('Z', '+00:00'))
            
            session['duration_minutes'] = int((last_activity - created_at).total_seconds() / 60)
            session['inactive_minutes'] = int((timezone.now() - last_activity).total_seconds() / 60)
            
            # Información de seguridad
            session['has_security_flags'] = len(session.get('flags', [])) > 0
            session['security_level'] = self._calculate_security_level(session)
        
        return {
            'sessions': sessions,
            'total_count': len(sessions),
            'active_locations': len(set(s['location']['country'] for s in sessions if s.get('location', {}).get('country'))),
            'unique_devices': len(set(s['device_fingerprint'] for s in sessions if s.get('device_fingerprint'))),
            'security_summary': self._get_sessions_security_summary(sessions)
        }
    
    def _calculate_security_level(self, session: Dict) -> str:
        """Calcula el nivel de seguridad de una sesión"""
        score = session.get('security_score', 50)
        flags = session.get('flags', [])
        
        if 'compromised' in flags:
            return 'compromised'
        elif score >= 80:
            return 'high'
        elif score >= 60:
            return 'medium'
        else:
            return 'low'
    
    def _get_sessions_security_summary(self, sessions: List[Dict]) -> Dict:
        """Resumen de seguridad de todas las sesiones"""
        if not sessions:
            return {'status': 'no_sessions', 'issues': 0}
        
        high_risk_count = sum(1 for s in sessions if s.get('security_score', 100) < 50)
        compromised_count = sum(1 for s in sessions if 'compromised' in s.get('flags', []))
        
        if compromised_count > 0:
            return {'status': 'critical', 'compromised_sessions': compromised_count}
        elif high_risk_count > 0:
            return {'status': 'warning', 'high_risk_sessions': high_risk_count}
        else:
            return {'status': 'good', 'issues': 0}
    
    def cleanup_all_expired_sessions(self):
        """Limpieza global de sesiones expiradas (para tarea cron)"""
        # Este método debería ser ejecutado periódicamente
        pattern = f"{self.session_prefix}*"
        
        try:
            # Nota: esto requiere Redis con SCAN support
            from django.core.cache.backends.redis import RedisCache
            if isinstance(cache, RedisCache):
                redis_conn = cache._cache.get_client()
                for key in redis_conn.scan_iter(match=pattern):
                    session_data = cache.get(key.decode())
                    if session_data:
                        session = json.loads(session_data)
                        if not self.is_session_valid(session):
                            cache.delete(key.decode())
                            logger.info(f"Cleaned up expired session: {key.decode()}")
        except Exception as e:
            logger.error(f"Error in global session cleanup: {e}")
    
    # Mantener métodos existentes con mejoras menores
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Obtiene información de una sesión"""
        session_key = f"{self.session_prefix}{session_id}"
        session_data = cache.get(session_key)
        
        if session_data:
            try:
                return json.loads(session_data)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in session {session_id}")
                cache.delete(session_key)
        return None
    
    def get_user_sessions(self, user_id: int) -> List[Dict]:
        """Obtiene todas las sesiones activas de un usuario"""
        sessions_key = f"{self.active_sessions_prefix}{user_id}"
        session_ids = cache.get(sessions_key, [])
        
        active_sessions = []
        expired_sessions = []
        
        for session_id in session_ids:
            session = self.get_session(session_id)
            if session and self.is_session_valid(session):
                # Calcular tiempo de inactividad
                last_activity = datetime.fromisoformat(session['last_activity'].replace('Z', '+00:00'))
                inactive_time = timezone.now() - last_activity
                session['inactive_minutes'] = int(inactive_time.total_seconds() / 60)
                
                active_sessions.append(session)
            else:
                expired_sessions.append(session_id)
        
        # Limpiar sesiones expiradas
        if expired_sessions:
            self.remove_sessions_from_active_list(user_id, expired_sessions)
        
        # Ordenar por actividad más reciente
        active_sessions.sort(key=lambda x: x['last_activity'], reverse=True)
        
        return active_sessions
    
    def terminate_session(self, session_id: str, user_id: int = None) -> bool:
        """Termina una sesión específica"""
        session = self.get_session(session_id)
        if not session:
            return False
        
        if user_id and session['user_id'] != user_id:
            logger.warning(f"Unauthorized session termination attempt - Session: {session_id}, User: {user_id}")
            return False
        
        # Eliminar datos relacionados
        session_key = f"{self.session_prefix}{session_id}"
        activity_key = f"{self.session_activity_prefix}{session_id}"
        
        cache.delete(session_key)
        cache.delete(activity_key)
        
        # Remover de lista activa
        self.remove_sessions_from_active_list(session['user_id'], [session_id])
        
        logger.info(f"Session terminated: {session_id} for user {session.get('username', 'unknown')}")
        
        return True
    
    def terminate_all_user_sessions(self, user_id: int, except_session: str = None) -> int:
        """Termina todas las sesiones de un usuario"""
        sessions = self.get_user_sessions(user_id)
        terminated_count = 0
        
        for session in sessions:
            if except_session and session['session_id'] == except_session:
                continue
                
            if self.terminate_session(session['session_id'], user_id):
                terminated_count += 1
        
        logger.info(f"Terminated {terminated_count} sessions for user {user_id}")
        return terminated_count
    
    def is_session_valid(self, session: Dict) -> bool:
        """Verifica si una sesión es válida"""
        if not session.get('is_active', True):
            return False
        
        if 'compromised' in session.get('flags', []):
            return False
        
        try:
            expires_at = datetime.fromisoformat(session['expires_at'].replace('Z', '+00:00'))
            return timezone.now() < expires_at
        except (ValueError, KeyError):
            return False
    
    # Métodos auxiliares existentes mejorados
    def create_device_fingerprint(self, user_agent: str, ip_address: str) -> str:
        """Crea un fingerprint del dispositivo"""
        # Agregar más datos para mejor fingerprinting
        fingerprint_data = f"{user_agent}|{ip_address}|{timezone.now().strftime('%Y%m%d')}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
    
    def get_client_ip(self, request) -> str:
        """Obtiene la IP real del cliente con validación mejorada"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Tomar la primera IP y validar formato
            ip = x_forwarded_for.split(',')[0].strip()
            try:
                import ipaddress
                ipaddress.ip_address(ip)  # Validar formato IP
                return ip
            except ValueError:
                pass
        
        remote_addr = request.META.get('REMOTE_ADDR', 'Unknown')
        return remote_addr if remote_addr != 'Unknown' else '127.0.0.1'
    
    def get_location_info(self, ip_address: str) -> Dict:
        """Información de geolocalización mejorada"""
        # Implementar con geoip2 o servicio externo en producción
        if ip_address in ['127.0.0.1', 'localhost', 'Unknown']:
            return {'country': 'Local', 'city': 'Local', 'region': 'Local'}
        
        # Ejemplo con datos mock - reemplazar con implementación real
        return {
            'country': 'España',  # Obtener de GeoIP
            'city': 'Madrid',
            'region': 'Madrid',
            'lat': 40.4168,
            'lon': -3.7038
        }
    
    def add_to_active_sessions(self, user_id: int, session_id: str):
        """Agrega sesión a lista activa con límite"""
        sessions_key = f"{self.active_sessions_prefix}{user_id}"
        session_ids = cache.get(sessions_key, [])
        
        if session_id not in session_ids:
            session_ids.append(session_id)
            
            # Aplicar límite de sesiones almacenadas
            if len(session_ids) > self.max_sessions_per_user * 2:
                session_ids = session_ids[-self.max_sessions_per_user:]
            
            cache.set(sessions_key, session_ids, timeout=self.session_timeout * 2)
    
    def remove_sessions_from_active_list(self, user_id: int, session_ids: List[str]):
        """Remueve sesiones de la lista activa"""
        sessions_key = f"{self.active_sessions_prefix}{user_id}"
        current_sessions = cache.get(sessions_key, [])
        
        updated_sessions = [sid for sid in current_sessions if sid not in session_ids]
        cache.set(sessions_key, updated_sessions, timeout=self.session_timeout * 2)
    
    def cleanup_expired_sessions(self, user_id: int):
        """Limpia sesiones expiradas de un usuario"""
        self.get_user_sessions(user_id)  # Esto ya hace la limpieza automática
    
    def get_session_statistics(self, user_id: int) -> Dict:
        """Estadísticas completas de sesiones del usuario"""
        detailed_data = self.get_user_sessions_detailed(user_id)
        sessions = detailed_data['sessions']
        
        if not sessions:
            return {
                'total_sessions': 0,
                'active_sessions': 0,
                'unique_devices': 0,
                'unique_locations': 0,
                'last_login': None,
                'security_summary': {'status': 'no_sessions'},
                'sessions': []
            }
        
        # Última sesión
        last_session = max(sessions, key=lambda x: x['created_at']) if sessions else None
        
        return {
            'total_sessions': len(sessions),
            'active_sessions': len(sessions),
            'unique_devices': detailed_data['unique_devices'],
            'unique_locations': detailed_data['active_locations'],
            'last_login': last_session['created_at'] if last_session else None,
            'security_summary': detailed_data['security_summary'],
            'sessions': sessions[:10],  # Limitar a 10 sesiones más recientes
            'total_activities': sum(s.get('activities_count', 0) for s in sessions),
            'average_session_duration': sum(s.get('duration_minutes', 0) for s in sessions) / len(sessions) if sessions else 0
        }