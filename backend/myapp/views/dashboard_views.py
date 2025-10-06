"""
Dashboard statistics and analytics views - CORREGIDO
"""

from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.utils import timezone
from datetime import timedelta

from ..models import PasswordEntry, EncryptedFile, ActivityLog, Vault


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_dashboard_stats(request):
    """API para estadísticas del dashboard incluyendo información de vaults"""
    try:
        user = request.user
        
        # Estadísticas básicas
        passwords_count = PasswordEntry.objects.filter(user=user).count()
        files_count = EncryptedFile.objects.filter(user=user).count()
        active_sessions = 1  # Hardcoded por ahora
        
        # Estadísticas de vaults
        vault_summary = get_vault_summary(user)
        
        # Score de seguridad
        strong_passwords = PasswordEntry.objects.filter(
            user=user, 
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        security_score = min(95, (strong_passwords / max(passwords_count, 1)) * 100)
        
        response_data = {
            'passwords_count': passwords_count,
            'files_count': files_count,
            'active_sessions': active_sessions,
            'security_score': round(security_score),
            'vault_summary': vault_summary
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated]) 
def api_recent_activity(request):
    """API para actividad reciente"""
    try:
        user = request.user
        activities = []
        
        # Obtener actividades del log si existe
        recent_logs = ActivityLog.objects.filter(user=user).order_by('-timestamp')[:4]
        
        if recent_logs.exists():
            for log in recent_logs:
                activities.append({
                    'type': log.activity_type,
                    'title': log.title,
                    'description': log.description,
                    'time': log.timestamp.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': log.severity
                })
        else:
            # Si no hay logs, generar datos basados en contraseñas y archivos recientes
            recent_passwords = PasswordEntry.objects.filter(user=user).order_by('-created_at')[:2]
            for pwd in recent_passwords:
                activities.append({
                    'type': 'password_created',
                    'title': 'Nueva contraseña generada',
                    'description': f'Contraseña segura generada para {pwd.website}',
                    'time': pwd.created_at.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': 'success'
                })
            
            recent_files = EncryptedFile.objects.filter(user=user).order_by('-uploaded_at')[:2]
            for file in recent_files:
                activities.append({
                    'type': 'file_encrypted',
                    'title': 'Archivo encriptado',
                    'description': f'{file.title} fue encriptado',
                    'time': file.uploaded_at.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': 'info'
                })
        
        return Response({'activities': activities[:4]}, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_security_summary(request):
    """API para resumen de seguridad"""
    try:
        user = request.user
        passwords = PasswordEntry.objects.filter(user=user)
        total_passwords = passwords.count()
        
        # Contraseñas seguras (usando algoritmos fuertes)
        strong_passwords = passwords.filter(
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        
        # Contraseñas que necesitan actualización (más de 365 días)
        needs_update = passwords.filter(
            updated_at__lt=timezone.now() - timedelta(days=365)
        ).count()
        
        # Contraseñas antiguas (más de 720 días)
        old_passwords = passwords.filter(
            created_at__lt=timezone.now() - timedelta(days=720)
        ).count()
        
        response_data = {
            'strong_passwords': strong_passwords,
            'needs_update': needs_update,
            'old_passwords': old_passwords,
            'total_passwords': total_passwords
        }
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        return Response(
            {'error': str(e)}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def get_vault_summary(user):
    """Gets a summary of user's vaults for dashboard"""
    try:
        vaults = Vault.objects.filter(user=user)
        total_passwords = PasswordEntry.objects.filter(user=user).count()
        unvaulted = PasswordEntry.objects.filter(user=user, vault__isnull=True).count()
        
        summary = {
            'total_vaults': vaults.count(),
            'private_vaults': vaults.filter(is_private=True).count(),
            'public_vaults': vaults.filter(is_private=False).count(),
            'unvaulted_passwords': unvaulted,
            'vaulted_passwords': total_passwords - unvaulted,
            'vault_list': []
        }
        
        for vault in vaults[:5]:  # Top 5 vaults
            summary['vault_list'].append({
                'id': vault.id,
                'name': vault.name,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count()
            })
        
        return summary
    except Exception as e:
        print(f"Error getting vault summary: {e}")
        return {
            'total_vaults': 0,
            'private_vaults': 0,
            'public_vaults': 0,
            'unvaulted_passwords': 0,
            'vaulted_passwords': 0,
            'vault_list': []
        }