# urls.py - Actualizar para servir React
from django.urls import path, re_path
from . import views
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    # APIs para React
    path("api/accounts/", views.api_accounts, name="api_accounts"),
    path("api/files/", views.api_files, name="api_files"), 
    path("api/settings/", views.api_user_settings, name="api_settings"),
    
    # Operaciones POST (mantener las existentes)
    path("register/", views.register, name="register"),
    path("login/", views.loginView, name='login'),
    path("logout/", views.logoutUser, name='logout'),
    path("accounts/createPassword/", views.add_password, name="create_password"),
    path('accounts/unlock/<int:password_id>/', views.unlock_password, name='unlock_password'),
    path('accounts/delete_password/<int:password_id>/', views.delete_password, name='delete_password'),
    path('accounts/update_password/<str:pk>/', views.update_password, name='update_password'),
    path('file-system/add-file', views.upload_file, name='upload_file'),
    path('decrypt-file/<int:file_id>/', views.download_file, name='download_file'),
    path('delete-file/<int:file_id>/', views.delete_file, name='delete_file'),
    path('file-system/delete_all/', views.delete_all_files, name='delete_all_files'),

    # Todas las rutas van a React (IMPORTANTE: esto va al final)
    re_path(r'^.*$', views.app_view, name='app'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)