from typing import Any
from django import forms
from django.forms import ModelForm
from .models import PasswordEntry
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



class PasswordForm(forms.Form):
    website = forms.CharField(max_length=255)
    username = forms.CharField(max_length=255)
    password = forms.CharField(widget=forms.PasswordInput)
    algorithm = forms.ChoiceField(choices=[('AES', 'AES'), ('ChaCha20', 'ChaCha20')], label="Encryption Algorithm")