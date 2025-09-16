"""
Dashboard statistics and analytics views
"""

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta

from ..models import PasswordEntry, EncryptedFile, ActivityLog, Vault
from ..utils.logging_utils import log_activity


@login_required
def api_dashboard_stats(request):
    """API para estadísticas del dashboard incluyendo información de vaults"""
    try:
        # Estadísticas básicas existentes
        passwords_count = PasswordEntry.objects.filter(user=request.user).count()
        files_count = EncryptedFile.objects.filter(user=request.user).count()
        active_sessions = 1  # Hardcoded por ahora
        
        # Estadísticas de vaults
        vault_summary = get_vault_summary(request.user)
        
        # Score de seguridad
        strong_passwords = PasswordEntry.objects.filter(
            user=request.user, 
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
        
        return JsonResponse(response_data)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required 
def api_recent_activity(request):
    """API para actividad reciente"""
    try:
        activities = []
        
        # Obtener actividades del log si existe
        recent_logs = ActivityLog.objects.filter(user=request.user)[:4]
        
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
            # Últimas contraseñas creadas
            recent_passwords = PasswordEntry.objects.filter(user=request.user).order_by('-created_at')[:2]
            for pwd in recent_passwords:
                activities.append({
                    'type': 'password_created',
                    'title': 'Nueva contraseña generada',
                    'description': f'Contraseña segura generada para {pwd.website}',
                    'time': pwd.created_at.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': 'success'
                })
            
            # Últimos archivos
            recent_files = EncryptedFile.objects.filter(user=request.user).order_by('-uploaded_at')[:2]
            for file in recent_files:
                activities.append({
                    'type': 'file_encrypted',
                    'title': 'Archivo encriptado',
                    'description': f'{file.title} fue encriptado',
                    'time': file.uploaded_at.strftime('%Y-%m-%d %H:%M'),
                    'activity_type': 'info'
                })
        
        return JsonResponse({'activities': activities[:4]})  # Últimas 4
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def api_security_summary(request):
    """API para resumen de seguridad"""
    try:
        passwords = PasswordEntry.objects.filter(user=request.user)
        total_passwords = passwords.count()
        
        # Contraseñas seguras (usando algoritmos fuertes)
        strong_passwords = passwords.filter(
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        
        # Contraseñas que necesitan actualización (más de 90 días)
        from django.utils import timezone
        from datetime import timedelta
        
        needs_update = passwords.filter(
            updated_at__lt=timezone.now() - timedelta(days=365)
        ).count()
        
        # Contraseñas antiguas (más de 180 días)
        old_passwords = passwords.filter(
            created_at__lt=timezone.now() - timedelta(days=720)
        ).count()
        
        return JsonResponse({
            'strong_passwords': strong_passwords,
            'needs_update': needs_update,
            'old_passwords': old_passwords,
            'total_passwords': total_passwords
        })
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    

def get_vault_summary(user):
    """Gets a summary of user's vaults for dashboard"""
    try:
        vaults = Vault.objects.filter(user=user)
        total_passwords = PasswordEntry.objects.filter(user=user).count()
        
        summary = {
            'total_vaults': vaults.count(),
            'private_vaults': vaults.filter(is_private=True).count(),
            'public_vaults': vaults.filter(is_private=False).count(),
            'unvaulted_passwords': PasswordEntry.objects.filter(user=user, vault__isnull=True).count(),
            'vaulted_passwords': total_passwords - PasswordEntry.objects.filter(user=user, vault__isnull=True).count(),
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
        return None
    