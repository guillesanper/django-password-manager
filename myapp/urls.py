from django.urls import path
from . import  views

urlpatterns = [
    path("", views.home, name = "home"),
    path("accounts/accounts/",views.viewAccs,name="accounts"),
    path("register/",views.register,name = "register"),
    path("login/",views.loginView,name='login'),
    path("logout/",views.logoutUser,name = 'logout'),
    path("accounts/createPassword/",views.add_password,name ="create_password"),
    path('accounts/unlock/<int:password_id>/', views.unlock_password, name='unlock_password'),
]