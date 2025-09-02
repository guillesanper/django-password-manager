# myapp/urls.py - URLs actualizadas con endpoints de clave maestra

from django.urls import path
from . import views

urlpatterns = [
    # Vista principal para la SPA
    path('', views.app_view, name='app'),
    
    path('metrics/', views.metrics_view, name='metrics'),
    
    # APIs de autenticación
    path('auth/login/', views.LoginView.as_view(), name='api_login'),
    path('auth/register/', views.RegisterView.as_view(), name='api_register'),
    path('auth/logout/', views.LogoutView.as_view(), name='api_logout'),
    path('auth/check/', views.check_auth_status, name='check_auth_status'),
    
    # APIs de clave maestra
    path('api/master-key/setup/', views.setup_master_key, name='setup_master_key'),
    path('api/master-key/check/', views.check_master_key, name='check_master_key'),
    path('api/master-key/verify/', views.verify_master_key, name='verify_master_key'),
    path('api/master-key/change/', views.change_master_key, name='change_master_key'),
    
    #APIs para obtener estadísticas
    path('api/dashboard/stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
    path('api/dashboard/recent-activity/', views.api_recent_activity, name='api_recent_activity'),
    path('api/dashboard/security-summary/', views.api_security_summary, name='api_security_summary'),
    
    # APIs de análisis de seguridad
    path('api/security/analysis/', views.api_security_analysis, name='api_security_analysis'),
    path('api/security/check-breach/', views.api_check_single_password_breach, name='api_check_single_password_breach'),  
    path('api/security/recommendations/', views.api_security_recommendations, name='api_security_recommendations'),
    
    # APIs de datos
    path('api/accounts/', views.api_accounts, name='api_accounts'),
    path('api/files/', views.api_files, name='api_files'),
    path('api/user-settings/', views.api_user_settings, name='api_user_settings'),
    path('api/password-generator/', views.api_password_generator, name='api_password_generator'),
    path('api/unlock-password/<int:password_id>/', views.api_unlock_password, name='api_unlock_password'),
    path('api/unlock-all-accounts/', views.api_unlock_all_accounts, name='api_unlock_all_accounts'),
    
    # Endpoints POST para formularios
    path('passwords/add/', views.add_password, name='add_password'),
    path('passwords/<int:password_id>/delete/', views.delete_password, name='delete_password'),
    path('passwords/<int:pk>/update/', views.update_password, name='update_password'),
    
    path('files/upload/', views.upload_file, name='upload_file'),
    path('files/<int:file_id>/download/', views.download_file, name='download_file'),
    path('files/<int:file_id>/delete/', views.delete_file, name='delete_file'),
    path('files/delete-all/', views.delete_all_files, name='delete_all_files'),
    
    path('settings/', views.settings_view, name='settings'),
    
    # Capturar todas las rutas del frontend para la SPA
    path('<path:path>', views.app_view, name='app_catchall'),
]