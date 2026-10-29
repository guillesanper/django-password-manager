from django import forms
from .models import UserSettings
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

class UserRegisterForm(UserCreationForm):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'type' :"email",'class':"form-control form-control-user",'placeholder':'Email Address'}))
    class Meta:
        model = User
        fields = ['username','email', 'password1', 'password2']
        widgets ={
            'username' : forms.TextInput(attrs={'type' :"username",'class':"form-control form-control-user",'placeholder':'Username'})
        }
    
    def __init__(self, *args, **kwargs):
        super(UserRegisterForm,self).__init__(*args, **kwargs)

        self.fields['password1'].widget.attrs['class']='form-control form-control-user'
        self.fields['password1'].widget.attrs['placeholder']='Password'
        self.fields['password2'].widget.attrs['class']='form-control form-control-user'
        self.fields['password2'].widget.attrs['placeholder']='Repeat password'

# Los formularios server-rendered de contraseñas y ficheros (PasswordUpdateForm, PasswordForm,
# EncryptedFileForm) se eliminaron en el paso 26: pertenecían al flujo v1 con cripto en servidor
# y referenciaban campos ya purgados (website/username/algorithm). La UI es una SPA que cifra en
# cliente; el servidor sólo maneja blobs opacos.

class SettingsForm(forms.ModelForm):
    class Meta:
        model = UserSettings
        fields = ['theme', 'require_password_modify', 'require_password_delete', 'notifications']
        widgets = {
            'theme': forms.Select(attrs={'class': 'form-control'}),
            'require_password_modify': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'require_password_delete': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'notifications': forms.Select(attrs={'class': 'form-control'}),
        }
    