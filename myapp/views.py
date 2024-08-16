from django.shortcuts import render,redirect,get_object_or_404
from django.contrib import messages

from .models import PasswordEntry,MasterKey
from .forms import UserRegisterForm,PasswordForm
from .encryption_utils import encrypt_password,decrypt_password

from django.contrib.auth import login,authenticate,logout
from django.contrib.auth.decorators import login_required

from base64 import urlsafe_b64decode,urlsafe_b64encode


@login_required(login_url='login')
def view_unlocked_accs(request):
    accounts = PasswordEntry.objects.filter(user=request.user)
    
    if request.method == 'POST':
        master_password = request.POST.get('master_password')
        if master_password:
            master_key_entry = get_object_or_404(MasterKey, user=request.user)
            if master_key_entry.verify_master_key(master_password):
                decrypted_accounts = []
                for account in accounts:
                    decrypted_password = decrypt_password(
                        account.encrypted_password, 
                        account.encrypted_key, 
                        account.iv_or_nonce, 
                        master_key_entry.hashed_key.encode(), 
                        account.encryption_algorithm
                    )
                    decrypted_accounts.append((account, decrypted_password))
                return render(request, 'accounts/accounts.html', {'accounts': decrypted_accounts, 'unlocked': True})

    return render(request, 'accounts/accounts.html', {'accounts': accounts, 'unlocked': False})

# Create your views here.
@login_required(login_url='login')
def home(request):
    return render(request,"home.html")

@login_required(login_url='login')
def viewAccs(request):
    accounts = PasswordEntry.objects.filter(user = request.user)
    return render(request,"accounts/accounts.html",{"accounts": accounts}) 

@login_required(login_url='login')
def add_password1(request):
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            # Obtener la entrada de la clave maestra del usuario actual desde la base de datos
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()  # Obtener la clave maestra almacenada

            password = form.cleaned_data['password']
            algorithm = form.cleaned_data['algorithm']
            
            # Cifrar la contraseña usando la clave maestra
            encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(password, master_key, algorithm)
            
            # Guardar la entrada cifrada en la base de datos
            PasswordEntry.objects.create(
                user=request.user,
                website=form.cleaned_data['website'],
                username=form.cleaned_data['username'],
                encrypted_password=encrypted_password,
                encryption_algorithm=algorithm,
                iv_or_nonce=iv_or_nonce,
                encrypted_key=encrypted_key,
                salt=entry_salt  # Almacenar la salt única para esta entrada
            )
            return redirect('accounts')

    else:
        form = PasswordForm()
    return render(request, 'accounts/account_form.html', {'form': form})



@login_required(login_url='login')
def add_password(request):
    if request.method == 'POST':
        form = PasswordForm(request.POST)
        if form.is_valid():
            # Obtener la entrada de la clave maestra del usuario actual desde la base de datos
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()  # Obtener la clave maestra almacenada

            password = form.cleaned_data['password']
            algorithm = form.cleaned_data['algorithm']
            
            # Cifrar la contraseña usando la clave maestra
            encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(password, master_key, algorithm)
            
            # Guardar la entrada cifrada en la base de datos
            password_entry = PasswordEntry.objects.create(
                user=request.user,
                website=form.cleaned_data['website'],
                username=form.cleaned_data['username'],
                encrypted_password=encrypted_password,
                encryption_algorithm=algorithm,
                iv_or_nonce=iv_or_nonce,  # Ya está codificado en base64, no necesitas codificarlo de nuevo
                encrypted_key=encrypted_key,
                salt=entry_salt  # Ya está codificado en base64, no necesitas codificarlo de nuevo
            )
            # password_entry.decrypted_password = decrypt_password(encrypted_password,encrypted_key,iv_or_nonce,master_key,entry_salt)
            return redirect('accounts')


    else:
        form = PasswordForm()
    return render(request, 'accounts/account_form.html', {'form': form})

@login_required(login_url='login')
def unlock_password(request, password_id):
    account = None  # Inicializa account con None
    error_message = None  # Inicializa un mensaje de error vacío

    if request.method == 'POST':
        master_password = request.POST.get('master_password')
        if master_password:
            master_key_entry = get_object_or_404(MasterKey, user=request.user)
            if master_key_entry.verify_master_key(master_password):
                account = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
                
                # Desencripta la contraseña usando la clave derivada de master_key
                decrypted_password = decrypt_password(
                    encrypted_password=account.encrypted_password,  # No se decodifica aquí
                    encrypted_key=account.encrypted_key, 
                    iv_or_nonce=account.iv_or_nonce,  # No se decodifica aquí
                    master_key=master_key_entry.hashed_key.encode(),  # Mantener como bytes
                    entry_salt=account.salt,  # No se decodifica aquí
                    algorithm=account.encryption_algorithm
                )
                account.decrypted_password = decrypted_password.decode('utf-8')  # Decodificar a cadena UTF-8
            else:
                error_message = "Master password incorrecta."
        else:
            error_message = "Debe ingresar una master password."

    if account is None:
        return render(request, 'accounts/unlocked_password.html', {'error_message': error_message})

    return render(request, 'accounts/unlocked_password.html', {'account': account})

# Authentication

def loginView(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        if request.method == 'POST':
            email = request.POST.get("email")
            password = request.POST.get("password")

            user = authenticate(request, email=email, password=password)

            if user is not None:
                login(request,user)
                return redirect('accounts') 
            else:
                # Si la autenticación falla, renderiza de nuevo el formulario con un mensaje de error
                context = {'error': 'Invalid email or password'}
                return render(request, 'users/login.html', context)     
        else:
            context = {}
            return render(request,'users/login.html',context)


def register(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        if request.method == 'POST':
            user_form = UserRegisterForm(request.POST)

            if user_form.is_valid():
                user = user_form.save()
                password = user_form.cleaned_data.get('password1')

                # Crear una instancia de MasterKey y establecer la master_key derivada
                master_key_instance = MasterKey.objects.create(user=user)
                master_key_instance.set_master_key(password)

                # Autenticar y loguear al usuario
                user = authenticate(username=user.username, password=password)
                login(request, user)

                messages.success(request, f'Account was created for {user.username}')
                return redirect('home')
            else:
                context = {'user_form': user_form}
                return render(request, 'users/register.html', context)
        else:
            user_form = UserRegisterForm()
            context = {'user_form': user_form}
            return render(request, 'users/register.html', context)



@login_required(login_url='login')
def logoutUser(request):
    logout(request)
    return render(request,'users/login.html',context={})

