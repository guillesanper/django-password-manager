# myapp/urls.py - URLs CORREGIDAS

from django.urls import path
from . import views

urlpatterns = [
    # =====================
    # APIs DEBEN IR PRIMERO
    # =====================
    
    # CSRF Token (debe ir muy arriba)
    path('api/csrf/', views.get_csrf_token, name='csrf_token'),
    
    # APIs de autenticación
    path('auth/login/', views.SecureLoginView.as_view(), name='api_login'),
    path('auth/register/', views.SecureRegisterView.as_view(), name='api_register'),
    path('auth/logout/', views.SecureLogoutView.as_view(), name='api_logout'),
    path('auth/check/', views.check_auth_status, name='check_auth_status'),
    
    # APIs de dashboard (CRÍTICO - estas están fallando)
    path('api/dashboard/stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
    path('api/dashboard/recent-activity/', views.api_recent_activity, name='api_recent_activity'),
    path('api/dashboard/security-summary/', views.api_security_summary, name='api_security_summary'),
    
    # APIs de análisis de seguridad
    path('api/security/analysis/', views.api_security_analysis, name='api_security_analysis'),
    path('api/security/check-breach/', views.api_check_single_password_breach, name='api_check_single_password_breach'),  
    path('api/security/recommendations/', views.api_security_recommendations, name='api_security_recommendations'),
    
    # APIs de gestión de sesiones
    path('api/sessions/', views.SessionManagementView.as_view(), name='api_sessions_management'),
    path('api/sessions/list/', views.api_get_user_sessions, name='api_get_user_sessions'),
    path('api/sessions/terminate/', views.api_terminate_session, name='api_terminate_session'),
    path('api/sessions/terminate-all/', views.api_terminate_all_sessions, name='api_terminate_all_sessions'),
    path('api/sessions/flag-suspicious/', views.api_flag_session_suspicious, name='api_flag_session_suspicious'),
    path('api/sessions/<str:session_id>/activities/', views.api_get_session_activities, name='api_get_session_activities'),
    path('api/sessions/security-report/', views.api_session_security_report, name='api_session_security_report'),
    path('api/sessions/refresh-security/', views.api_refresh_session_security, name='api_refresh_session_security'),
    
    # APIs de clave maestra
    path('api/master-key/setup/', views.setup_master_key, name='setup_master_key'),
    path('api/master-key/check/', views.check_master_key, name='check_master_key'),
    path('api/master-key/verify/', views.verify_master_key, name='verify_master_key'),
    path('api/master-key/change/', views.change_master_key, name='change_master_key'),
    
    # APIs de datos
    path('api/accounts/', views.api_accounts, name='api_accounts'),
    path('api/files/', views.api_files, name='api_files'),
    path('api/user-settings/', views.api_user_settings, name='api_user_settings'),
    path('api/password-generator/', views.api_password_generator, name='api_password_generator'),
    path('api/unlock-password/<int:password_id>/', views.api_unlock_password, name='api_unlock_password'),
    path('api/unlock-all-accounts/', views.api_unlock_all_accounts, name='api_unlock_all_accounts'),
    
    # APIs de archivos para MinIO
    path('api/files/upload/', views.upload_file_combined, name='upload_file'),
    path('api/files/<int:file_id>/download/', views.download_file_combined, name='download_file'),
    path('api/files/<int:file_id>/delete/', views.delete_file_combined, name='delete_file'),
    path('api/files/delete-all/', views.delete_all_files_combined, name='delete_all_files'),
    
    # APIs de vaults
    path('api/vaults/', views.api_vaults, name='api_vaults'),
    path('api/vaults/create/', views.api_create_vault, name='api_create_vault'),
    path('api/vaults/<int:vault_id>/', views.api_update_vault, name='api_update_vault'),
    path('api/vaults/<int:vault_id>/delete/', views.api_delete_vault, name='api_delete_vault'),
    path('api/vaults/<int:vault_id>/unlock/', views.api_unlock_vault, name='api_unlock_vault'),
    path('api/vaults/<int:vault_id>/passwords/', views.api_vault_passwords, name='api_vault_passwords'),
    
    # APIs de contraseñas
    path('api/passwords/unvaulted/', views.api_unvaulted_passwords, name='api_unvaulted_passwords'),
    path('api/passwords/move/', views.api_move_password_to_vault, name='api_move_password_to_vault'),
    path('api/batch-delete-passwords/', views.api_batch_delete_passwords, name='api_batch_delete_passwords'),
    path('api/batch-move-passwords/', views.api_batch_move_passwords, name='api_batch_move_passwords'),
    
    # ==========================================
    # ENDPOINTS POST PARA FORMULARIOS (NO API)
    # ==========================================
    path('passwords/add/', views.add_password_with_vault_support, name='add_password'),
    path('passwords/<int:password_id>/delete/', views.delete_password, name='delete_password'),
    path('passwords/<int:pk>/update/', views.update_password, name='update_password'),
    
    # ==========================================
    # RUTAS ESPECÍFICAS (NO API)
    # ==========================================
    path('settings/', views.settings_view, name='settings'),
    path('metrics/', views.metrics_view, name='metrics'),
    path('health/', views.health_check, name='health_check'),
    
    # ==========================================
    # VISTA PRINCIPAL PARA LA SPA
    # ==========================================
    # IMPORTANTE: Esta debe ir AL FINAL
    path('', views.app_view, name='app'),
    
    # ==========================================
    # CATCH-ALL DEBE SER LA ÚLTIMA RUTA
    # ==========================================
    # Esta captura todas las rutas restantes para la SPA
    path('<path:path>', views.app_view, name='app_catchall'),
]