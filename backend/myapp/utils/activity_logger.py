# utils/activity_logger.py
from ..models import ActivityLog

def log_activity(user, activity_type, title, description, severity='info', related_obj=None):
    """
    Registra una actividad del usuario en el log
    
    Args:
        user: Usuario que realizó la actividad
        activity_type: Tipo de actividad (ver ActivityLog.ACTIVITY_TYPES)
        title: Título breve de la actividad
        description: Descripción detallada
        severity: Nivel de severidad ('success', 'info', 'warning', 'error')
        related_obj: Objeto relacionado (opcional)
    """
    try:
        ActivityLog.objects.create(
            user=user,
            activity_type=activity_type,
            title=title,
            description=description,
            severity=severity,
            related_object_type=type(related_obj).__name__ if related_obj else None,
            related_object_id=related_obj.id if related_obj else None
        )
    except Exception as e:
        # En caso de error al crear el log, no queremos interrumpir la operación principal
        print(f"Error logging activity: {e}")
        pass