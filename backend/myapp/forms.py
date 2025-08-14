from typing import Any
from django import forms
from django.forms import ModelForm
from .models import PasswordEntry, EncryptedFile,UserSettings
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

class PasswordUpdateForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': "form-control form-control-user",
            'placeholder': 'Password'
        }),
        required=False,
        help_text="Deja en blanco para mantener la contraseña actual."
    )

    algorithm = forms.ChoiceField(
        choices=[('AES', 'AES'), ('ChaCha20', 'ChaCha20')],
        label="Encryption Algorithm",
        widget=forms.Select(attrs={
            'class': "form-control  form-select"
        })
    )
    class Meta:
        model = PasswordEntry
        fields = ['website', 'username']
        widgets = {
            'username': forms.TextInput(attrs={'type': "username", 'class': "form-control form-control-user", 'placeholder': 'Username'}),
            'website': forms.TextInput(attrs={'type': "website", 'class': "form-control form-control-user", 'placeholder': 'Website'}),
            #'encryption_algorithm': forms.Select(attrs={'class': 'form-control form-select'})
        }       

class PasswordForm(forms.Form):
    website = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': "form-control form-control-user",
            'placeholder': 'Website'
        })
    )
    username = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={
            'class': "form-control form-control-user",
            'placeholder': 'Username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': "form-control form-control-user",
            'placeholder': 'Password'
        })
    )
    algorithm = forms.ChoiceField(
        choices=[('AES', 'AES'), ('ChaCha20', 'ChaCha20')],
        label="Encryption Algorithm",
        widget=forms.Select(attrs={
            'class': "form-control  form-select"
        })
    )

class EncryptedFileForm(forms.ModelForm):
    # Definimos el campo de elección de algoritmo aquí, no en widgets
    algorithm = forms.ChoiceField(
        choices=[('AES', 'AES'), ('ChaCha20', 'ChaCha20')],
        label="Encryption Algorithm",
        widget=forms.Select(attrs={
            'class': 'form-control form-select'
        })
    )

    class Meta:
        model = EncryptedFile
        fields = ['encrypted_file', 'algorithm']  # Incluimos algorithm en los fields
        widgets = {
            'encrypted_file': forms.ClearableFileInput(attrs={'class': 'form-control-file'}),
        }
        
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
    