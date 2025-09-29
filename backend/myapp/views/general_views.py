"""
General application views - main app view, settings, user management, metrics
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import JsonResponse, HttpResponse
from django.contrib.auth.models import User
from django.db import connection
from django.utils import timezone


from ..models import UserSettings
from ..forms import SettingsForm


# ==========================================
# MAIN APP VIEW FOR REACT SPA
# ==========================================

def app_view(request, path=''):
    """
    Main view for the SPA that handles all frontend routes.
    Accepts an optional path parameter for catch-all.
    """
    # If it's a request for metrics, return Prometheus metrics
    if path == 'metrics' or request.path == '/metrics':
        return metrics_view(request)
    
    # For any other route, serve the SPA
    return render(request, 'base.html')


# ==========================================
# USER SETTINGS
# ==========================================

@login_required
def api_user_settings(request):
    """API for user settings"""
    settings_obj, created = UserSettings.objects.get_or_create(user=request.user)
    data = {
        'theme': settings_obj.theme,
        'require_password_modify': settings_obj.require_password_modify,
        'require_password_delete': settings_obj.require_password_delete,
        'notifications': settings_obj.notifications
    }
    return JsonResponse(data)


@login_required
def settings_view(request):
    """Settings view"""
    user_settings, created = UserSettings.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = SettingsForm(request.POST, instance=user_settings)
        if form.is_valid():
            form.save()
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'success': True, 'message': 'Settings updated successfully'})
            messages.success(request, 'Configuraciones actualizadas correctamente.')
            return redirect('app')
        else:
            if request.headers.get('Accept') == 'application/json':
                return JsonResponse({'error': 'Form validation failed', 'errors': form.errors}, status=400)
            messages.error(request, 'Hubo un error al actualizar las configuraciones.')
    
    return app_view(request)


# ==========================================
# UTILITY APIs
# ==========================================

@login_required
def api_password_generator(request):
    """API for password generation"""
    # Default parameters or from query params
    count = int(request.GET.get('count', 5))
    length = int(request.GET.get('length', 20))
    use_special = request.GET.get('special', 'true').lower() == 'true'
    use_numbers = request.GET.get('numbers', 'true').lower() == 'true'
    
    from ..encryption_utils import generate_passwords
    passwords = generate_passwords(count, length, use_special, use_numbers)
    return JsonResponse({'passwords': passwords})


# ==========================================
# METRICS
# ==========================================

def metrics_view(request):
    """
    View to serve Prometheus metrics.
    """
    try:
        user_count = User.objects.count()
        
        metrics_data = f"""
# HELP django_users_total Total number of users
# TYPE django_users_total gauge
django_users_total {user_count}

# HELP django_db_connections Database connections
# TYPE django_db_connections gauge
django_db_connections {len(connection.queries) if connection.queries else 0}
"""
        
        return HttpResponse(
            metrics_data, 
            content_type='text/plain; version=0.0.4; charset=utf-8'
        )
    except Exception as e:
        return HttpResponse(
            f"# Error generating metrics: {str(e)}\n",
            content_type='text/plain; version=0.0.4; charset=utf-8',
            status=500
        )
        
        
# Vista de health check simple
@require_http_methods(["GET"])
def health_check(request):
    """Simple health check endpoint"""
    return JsonResponse({
        'status': 'ok',
        'timestamp': timezone.now().isoformat()
    })