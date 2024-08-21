from django.urls import path
from . import  views
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    path("", views.home, name = "home"),
    path("accounts/accounts/",views.viewAccs,name="accounts"),
    path("register/",views.register,name = "register"),
    path("login/",views.loginView,name='login'),
    path("logout/",views.logoutUser,name = 'logout'),
    path("accounts/createPassword/",views.add_password,name ="create_password"),
    path('accounts/unlock/<int:password_id>/', views.unlock_password, name='unlock_password'),
    path('accounts/delete_password/<int:password_id>/',views.delete_password,name = 'delete_password'),
    path('password-generator/password-generator/', views.password_generator, name='password_generator'),
    path('file-system/list-files',views.file_list,name='list_files'),
    path('file-system/add-file',views.upload_file,name='upload_file'),
    path('decrypt-file/<int:file_id>/', views.download_file, name='download_file'),
    path('delete-file/<int:file_id>/', views.delete_file, name='delete_file'),
    path('file-system/delete_all/',views.delete_all_files,name='delete_all_files')
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)