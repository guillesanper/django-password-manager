# session_views.py - Vistas mejoradas para gestión de sesiones
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from ..authentication import CookieJWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.core.paginator import Paginator
import json
import logging
from datetime import datetime, timedelta
from django.utils import timezone

from ..session_manager import SessionManager
from ..models import ActivityLog, SecurityEvent
from ..utils.request_utils import get_client_ip

logger = logging.getLogger('session')

class SessionManagementView(APIView):
    """Vista principal para gestión de sesiones con funcionalidad completa"""
    permission_classes = [IsAuthenticated]
    authentication_classes = [CookieJWTAuthentication]

    
    def __init__(self):
        super().__init__()
        self.session_manager = SessionManager()
    
    def get(self, request):
        """Obtiene información completa de sesiones del usuario"""
        try:
            # Parámetros de paginación y filtros
            page = int(request.GET.get('page', 1))
            per_page = min(int(request.GET.get('per_page', 10)), 50)  # Máximo 50
            include_activities = request.GET.get('include_activities', 'false').lower() == 'true'
            
            # Obtener sesiones detalladas
            sessions_data = self.session_manager.get_user_sessions_detailed(request.user.id)
            
            # Marcar la sesión actual
            current_session_id = getattr(request, 'session_id', None)
            for session in sessions_data['sessions']:
                session['is_current'] = session['session_id'] == current_session_id
            
            # Paginación
            sessions = sessions_data['sessions']
            paginator = Paginator(sessions, per_page)
            page_obj = paginator.get_page(page)
            
            # Preparar respuesta
            response_data = {
                'success': True,
                'sessions': {
                    'data': list(page_obj),
                    'pagination': {
                        'current_page': page,
                        'total_pages': paginator.num_pages,
                        'total_sessions': paginator.count,
                        'per_page': per_page,
                        'has_next': page_obj.has_next(),
                        'has_previous': page_obj.has_previous()
                    }
                },
                'statistics': {
                    'total_sessions': sessions_data['total_count'],
                    'unique_devices': sessions_data['unique_devices'],
                    'active_locations': sessions_data['active_locations'],
                    'security_summary': sessions_data['security_summary']
                }
            }
            
            return JsonResponse(response_data)
            
        except ValueError:
            logger.exception("Parámetros de paginación inválidos en api_get_user_sessions")
            return JsonResponse({
                'success': False,
                'error': 'Parámetros inválidos'
            }, status=400)
        except Exception as e:
            logger.error(f"Error obteniendo sesiones del usuario {request.user.id}: {e}")
            return JsonResponse({
                'success': False,
                'error': 'Error al obtener sesiones'
            }, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_get_user_sessions(request):
    """API endpoint simplificada para obtener sesiones activas"""
    try:
        session_manager = SessionManager()
        sessions_data = session_manager.get_session_statistics(request.user.id)
        
        # Marcar la sesión actual
        current_session_id = getattr(request, 'session_id', None)
        if current_session_id:
            for session in sessions_data.get('sessions', []):
                if session['session_id'] == current_session_id:
                    session['is_current'] = True
                    break
        
        return JsonResponse({
            'success': True,
            'sessions': sessions_data
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo sesiones del usuario {request.user.id}: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error al obtener sesiones'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_terminate_session(request):
    """Termina una sesión específica con validaciones mejoradas"""
    try:
        data = json.loads(request.body)
        session_id = data.get('session_id')
        reason = data.get('reason', 'user_request')  # Razón de terminación
        
        if not session_id:
            return JsonResponse({
                'success': False,
                'error': 'ID de sesión requerido'
            }, status=400)
        
        session_manager = SessionManager()
        
        # Verificar que no sea la sesión actual
        current_session_id = getattr(request, 'session_id', None)
        if session_id == current_session_id:
            return JsonResponse({
                'success': False,
                'error': 'No puedes terminar tu sesión actual'
            }, status=400)
        
        # Obtener información de la sesión antes de eliminarla
        session_info = session_manager.get_session(session_id)
        if not session_info:
            return JsonResponse({
                'success': False,
                'error': 'Sesión no encontrada'
            }, status=404)
        
        # Verificar que pertenece al usuario
        if session_info['user_id'] != request.user.id:
            logger.warning(f"Unauthorized session termination attempt by user {request.user.id} for session {session_id}")
            return JsonResponse({
                'success': False,
                'error': 'No autorizado'
            }, status=403)
        
        if session_manager.terminate_session(session_id, request.user.id):
            # Registrar actividad de terminación de sesión
            ActivityLog.objects.create(
                user=request.user,
                activity_type='session_terminated',
                title='Sesión terminada',
                description=f'Sesión terminada manualmente: {session_info.get("device_info", {}).get("browser", "Unknown")} desde {session_info.get("ip_address", "Unknown")}',
                severity='info',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                additional_data={
                    'terminated_session_id': session_id,
                    'reason': reason,
                    'terminated_device': session_info.get('device_info'),
                    'terminated_ip': session_info.get('ip_address')
                }
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Sesión terminada exitosamente'
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'No se pudo terminar la sesión'
            }, status=400)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        logger.error(f"Error terminando sesión: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_terminate_all_sessions(request):
    """Termina todas las demás sesiones del usuario"""
    try:
        data = json.loads(request.body)
        reason = data.get('reason', 'user_request_all')
        confirm = data.get('confirm', False)  # Confirmación explícita
        
        if not confirm:
            return JsonResponse({
                'success': False,
                'error': 'Confirmación requerida para terminar todas las sesiones'
            }, status=400)
        
        session_manager = SessionManager()
        current_session_id = getattr(request, 'session_id', None)
        
        # Obtener información de sesiones antes de terminarlas
        sessions_before = session_manager.get_user_sessions(request.user.id)
        sessions_to_terminate = [s for s in sessions_before if s['session_id'] != current_session_id]
        
        terminated_count = session_manager.terminate_all_user_sessions(
            request.user.id, 
            except_session=current_session_id
        )
        
        # Registrar actividad
        ActivityLog.objects.create(
            user=request.user,
            activity_type='all_sessions_terminated',
            title='Todas las sesiones terminadas',
            description=f'Se terminaron {terminated_count} sesiones adicionales',
            severity='warning',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'terminated_count': terminated_count,
                'reason': reason,
                'terminated_sessions': [
                    {
                        'session_id': s['session_id'],
                        'device': s.get('device_info', {}).get('browser', 'Unknown'),
                        'ip': s.get('ip_address', 'Unknown')
                    } for s in sessions_to_terminate
                ]
            }
        )
        
        return JsonResponse({
            'success': True,
            'message': f'{terminated_count} sesiones terminadas',
            'terminated_count': terminated_count
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        logger.error(f"Error terminando todas las sesiones: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_flag_session_suspicious(request):
    """Marca una sesión como sospechosa"""
    try:
        data = json.loads(request.body)
        session_id = data.get('session_id')
        reason = data.get('reason', 'user_report')
        
        if not session_id:
            return JsonResponse({
                'success': False,
                'error': 'ID de sesión requerido'
            }, status=400)
        
        session_manager = SessionManager()
        
        # Verificar que la sesión existe y pertenece al usuario
        session_info = session_manager.get_session(session_id)
        if not session_info or session_info['user_id'] != request.user.id:
            return JsonResponse({
                'success': False,
                'error': 'Sesión no encontrada o no autorizada'
            }, status=404)
        
        # Marcar como comprometida
        session_manager.flag_session_as_compromised(session_id, reason)
        
        # Registrar evento de seguridad
        SecurityEvent.objects.create(
            user=request.user,
            event_type='session_flagged_suspicious',
            description=f'Usuario marcó sesión {session_id} como sospechosa',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            additional_data={
                'flagged_session_id': session_id,
                'reason': reason,
                'flagged_device': session_info.get('device_info'),
                'flagged_ip': session_info.get('ip_address')
            }
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Sesión marcada como sospechosa'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        logger.error(f"Error marcando sesión como sospechosa: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_get_session_activities(request, session_id):
    """Obtiene las actividades de una sesión específica"""
    try:
        session_manager = SessionManager()
        
        # Verificar que la sesión existe y pertenece al usuario
        session_info = session_manager.get_session(session_id)
        if not session_info or session_info['user_id'] != request.user.id:
            return JsonResponse({
                'success': False,
                'error': 'Sesión no encontrada o no autorizada'
            }, status=404)
        
        activities = session_manager.get_session_activities(session_id)
        
        return JsonResponse({
            'success': True,
            'session_id': session_id,
            'activities': activities,
            'total_activities': len(activities)
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo actividades de sesión {session_id}: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error al obtener actividades'
        }, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_session_security_report(request):
    """Genera un reporte de seguridad de sesiones del usuario"""
    try:
        session_manager = SessionManager()
        sessions_data = session_manager.get_user_sessions_detailed(request.user.id)
        
        # Analizar patrones de seguridad
        security_report = {
            'user_id': request.user.id,
            'generated_at': timezone.now().isoformat(),
            'summary': sessions_data['security_summary'],
            'metrics': {
                'total_sessions': sessions_data['total_count'],
                'unique_locations': sessions_data['active_locations'],
                'unique_devices': sessions_data['unique_devices'],
            },
            'security_analysis': {
                'high_risk_sessions': 0,
                'compromised_sessions': 0,
                'unusual_locations': [],
                'unusual_devices': [],
                'time_patterns': {}
            },
            'recommendations': []
        }
        
        # Analizar cada sesión
        for session in sessions_data['sessions']:
            security_level = session.get('security_level', 'medium')
            
            if security_level == 'low' or session.get('security_score', 100) < 50:
                security_report['security_analysis']['high_risk_sessions'] += 1
            
            if 'compromised' in session.get('flags', []):
                security_report['security_analysis']['compromised_sessions'] += 1
            
            # Detectar ubicaciones inusuales
            location = session.get('location', {})
            if location and location.get('country') not in ['España', 'Local']:
                security_report['security_analysis']['unusual_locations'].append({
                    'session_id': session['session_id'],
                    'location': location,
                    'created_at': session['created_at']
                })
        
        # Generar recomendaciones
        if security_report['security_analysis']['high_risk_sessions'] > 0:
            security_report['recommendations'].append({
                'type': 'terminate_risky_sessions',
                'priority': 'high',
                'message': f'Considera terminar {security_report["security_analysis"]["high_risk_sessions"]} sesiones de alto riesgo'
            })
        
        if len(sessions_data['sessions']) > 3:
            security_report['recommendations'].append({
                'type': 'too_many_sessions',
                'priority': 'medium',
                'message': 'Tienes muchas sesiones activas, considera terminar las que no uses'
            })
        
        if security_report['security_analysis']['unusual_locations']:
            security_report['recommendations'].append({
                'type': 'unusual_locations',
                'priority': 'high',
                'message': 'Se detectaron accesos desde ubicaciones inusuales'
            })
        
        return JsonResponse({
            'success': True,
            'security_report': security_report
        })
        
    except Exception as e:
        logger.error(f"Error generando reporte de seguridad para usuario {request.user.id}: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error al generar reporte de seguridad'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_refresh_session_security(request):
    """Actualiza el análisis de seguridad de la sesión actual"""
    try:
        current_session_id = getattr(request, 'session_id', None)
        
        if not current_session_id:
            return JsonResponse({
                'success': False,
                'error': 'No hay sesión activa'
            }, status=400)
        
        session_manager = SessionManager()
        
        # Validar seguridad de la sesión actual
        security_validation = session_manager.validate_session_security(current_session_id, request)
        
        if not security_validation['valid']:
            # Si la sesión no es válida, marcarla como comprometida
            session_manager.flag_session_as_compromised(
                current_session_id, 
                f"Security validation failed: {', '.join(security_validation.get('issues', []))}"
            )
            
            # Registrar evento de seguridad
            SecurityEvent.objects.create(
                user=request.user,
                event_type='session_security_validation_failed',
                description=f'Validación de seguridad falló para sesión actual',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                additional_data={
                    'session_id': current_session_id,
                    'validation_issues': security_validation.get('issues', []),
                    'action_required': security_validation.get('action_required', False)
                }
            )
            
            return JsonResponse({
                'success': False,
                'security_valid': False,
                'issues': security_validation.get('issues', []),
                'action_required': security_validation.get('action_required', False),
                'message': 'Se detectaron problemas de seguridad en tu sesión'
            }, status=403)
        
        # Actualizar actividad de la sesión
        session_manager.update_session_activity(current_session_id, 'security_refresh')
        
        return JsonResponse({
            'success': True,
            'security_valid': True,
            'message': 'Seguridad de sesión verificada correctamente'
        })
        
    except Exception as e:
        logger.error(f"Error validando seguridad de sesión: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error al validar seguridad'
        }, status=500)