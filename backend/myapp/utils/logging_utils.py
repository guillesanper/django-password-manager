import logging
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType
from ..models import ActivityLog, SecurityEvent

# Configure loggers
activity_logger = logging.getLogger('audit')
security_logger = logging.getLogger('security')

def log_activity(user, activity_type, title, description, severity='info', 
                related_obj=None, ip_address=None, user_agent=None, additional_data=None):
    """
    Log de actividad mejorado con más contexto y seguridad
    
    Args:
        user: Usuario que realiza la actividad
        activity_type: Tipo de actividad (debe estar en ActivityLog.ACTIVITY_TYPES)
        title: Título corto de la actividad
        description: Descripción detallada
        severity: Nivel de severidad ('success', 'info', 'warning', 'error', 'critical')
        related_obj: Objeto relacionado (PasswordEntry, EncryptedFile, etc.)
        ip_address: IP del cliente
        user_agent: User agent del navegador
        additional_data: Datos adicionales en formato dict
    """
    try:
        # Determinar información del objeto relacionado
        related_object_type = None
        related_object_id = None
        
        if related_obj:
            related_object_type = related_obj.__class__.__name__
            related_object_id = related_obj.id
        
        # Crear el log de actividad
        activity_log = ActivityLog.objects.create(
            user=user,
            activity_type=activity_type,
            title=title,
            description=description,
            severity=severity,
            related_object_type=related_object_type,
            related_object_id=related_object_id,
            ip_address=ip_address,
            user_agent=user_agent or ''
        )
        
        # Log en archivo según la severidad
        log_message = (
            f"User: {user.username} | Type: {activity_type} | "
            f"Title: {title} | Description: {description} | "
            f"IP: {ip_address} | Severity: {severity}"
        )
        
        if severity in ['critical', 'error']:
            security_logger.error(log_message)
        elif severity == 'warning':
            security_logger.warning(log_message)
        else:
            activity_logger.info(log_message)
        
        # Crear evento de seguridad si es crítico
        if severity == 'critical':
            create_security_event(
                user=user,
                event_type='suspicious_activity',
                description=f"Critical activity logged: {title}",
                ip_address=ip_address,
                user_agent=user_agent,
                additional_data={
                    'activity_log_id': activity_log.id,
                    'original_description': description,
                    **(additional_data or {})
                }
            )
        
        return activity_log
        
    except Exception as e:
        security_logger.error(f"Failed to log activity for user {user.username}: {e}")
        return None

def create_security_event(event_type, description, user=None, ip_address=None, 
                         user_agent=None, additional_data=None):
    """
    Crear evento de seguridad crítico
    
    Args:
        event_type: Tipo de evento de seguridad
        description: Descripción del evento
        user: Usuario involucrado (puede ser None para eventos anónimos)
        ip_address: IP del origen del evento
        user_agent: User agent
        additional_data: Datos adicionales en formato dict
    """
    try:
        security_event = SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            description=description,
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent or '',
            additional_data=additional_data or {}
        )
        
        # Log crítico en archivo
        log_message = (
            f"SECURITY EVENT | Type: {event_type} | "
            f"User: {user.username if user else 'Anonymous'} | "
            f"Description: {description} | IP: {ip_address}"
        )
        security_logger.critical(log_message)
        
        return security_event
        
    except Exception as e:
        security_logger.error(f"Failed to create security event: {e}")
        return None

def log_minio_activity(user, action, filename, success=True, error_msg=None):
    """
    Logger específico para actividades de MinIO
    """
    severity = 'success' if success else 'error'
    description = f"MinIO {action}: {filename}"
    
    if not success and error_msg:
        description += f" - Error: {error_msg}"
    
    activity_type = {
        'upload': 'file_uploaded',
        'download': 'file_downloaded', 
        'delete': 'file_deleted'
    }.get(action, 'file_uploaded')
    
    return log_activity(
        user=user,
        activity_type=activity_type,
        title=f"File {action}",
        description=description,
        severity=severity
    )

# Reexportados desde request_utils, que es la única implementación (A4). Se
# mantienen aquí los nombres para no romper importaciones existentes.
from .request_utils import get_client_ip, get_user_agent  # noqa: F401,E402