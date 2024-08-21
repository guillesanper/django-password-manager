from django.shortcuts import render,redirect,get_object_or_404,HttpResponse
from django.contrib import messages
from django.core.files.storage import FileSystemStorage
from django.conf import settings

import os
import uuid

from .models import PasswordEntry,MasterKey,EncryptedFile,UserSettings
from .forms import UserRegisterForm,PasswordForm,EncryptedFileForm,PasswordUpdateForm,SettingsForm
from .encryption_utils import encrypt_password,decrypt_password,generate_passwords,encrypt_file,decrypt_file


from django.contrib.auth import login,authenticate,logout
from django.contrib.auth.decorators import login_required



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
def password_generator(request):
    passwords = generate_passwords(5,20,True,True)  # Genera 5 contraseñas
    context = {
        'passwords': passwords
    }
    return render(request, 'password_generator/password_generator.html', context)

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

@login_required(login_url='login')
def delete_password(request, password_id):
    password_entry = None
    error_message = None
    if request.method == 'POST':
        master_password = request.POST.get('master_password')
        if master_password:
            master_key_entry = get_object_or_404(MasterKey, user=request.user)
            if master_key_entry.verify_master_key(master_password):
                password_entry = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
                password_entry.delete()
                return redirect('accounts')  # Redirige después de eliminar
            else:
                error_message = "Master password incorrecta."
        else:
            error_message = "Debe ingresar una master password."
    
    if master_password == "klk":
        error_message = 'Parece que klk, no es tu contraseña,pero klk manin'
    
    # Si hay un error, renderiza la página con el mensaje de error
    return render(request, 'accounts/delete_password.html', {'error_message': error_message})


@login_required(login_url='login')
def update_password(request,pk):
    password_entry = get_object_or_404(PasswordEntry, id=pk, user=request.user)
    
    if request.method == 'POST':
        form = PasswordUpdateForm(request.POST, instance=password_entry)
        if form.is_valid():
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()

            #Si el usuario proporciona una nueva contraseña, la encriptamos
            if form.cleaned_data['password']:
                password = form.cleaned_data['password']
                algorithm = form.cleaned_data['algorithm']
                
                # Cifrar la nueva contraseña
                encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
                    password, master_key, algorithm
                )
                
                # Actualizar los campos cifrados
                password_entry.encrypted_password = encrypted_password
                password_entry.encrypted_key = encrypted_key
                password_entry.iv_or_nonce = iv_or_nonce
                password_entry.salt = entry_salt
                password_entry.encryption_algorithm = algorithm
            
            # Actualizar otros campos del modelo
            password_entry.website = form.cleaned_data['website']
            password_entry.username = form.cleaned_data['username']
            password_entry.save()

            messages.success(request, 'Password entry updated successfully!')
            return redirect('accounts')
    else:
        form = PasswordUpdateForm(instance=password_entry)
    
    context = {
        'form': form,
        'password_entry': password_entry
    }
    return render(request, 'accounts/account_form.html', context)
# Archivos

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = EncryptedFileForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['encrypted_file']
            original_file_name = uploaded_file.name

            # Guardar el archivo temporalmente en el sistema de archivos
            fs = FileSystemStorage()
            temp_filename = fs.save(original_file_name, uploaded_file)
            temp_file_path = fs.path(temp_filename)

            # Encriptar el archivo
            encrypted_file_key, iv_or_nonce, salt = encrypt_file(temp_file_path, request.user.password.encode())

            # Crear un nuevo nombre para el archivo encriptado
            encrypted_file_name = original_file_name + '.enc'
            encrypted_file_path = os.path.join(fs.location, encrypted_file_name)

            # Si ya existe un archivo con el nombre encriptado, eliminarlo
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

            # Crear una instancia de EncryptedFile
            file_entry = EncryptedFile(
                user=request.user,
                title=original_file_name,
                file_path=encrypted_file_path,  # Guardamos la ruta del archivo encriptado
                encrypted_key=encrypted_file_key,
                iv_or_nonce=iv_or_nonce,
                salt=salt,
                algorithm=form.cleaned_data['algorithm']
            )
            file_entry.save()

            return redirect('list_files')
    else:
        form = EncryptedFileForm()
    
    return render(request, 'files/upload_file.html', {'form': form})

@login_required
def download_file(request, file_id):
    # Obtener la entrada del archivo encriptado de la base de datos
    file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
    
    # Obtener la ruta del archivo encriptado desde la base de datos
    encrypted_file_path = file_entry.file_path
    
    # Generar el nombre y la ruta del archivo desencriptado
    original_file_name = file_entry.title
    decrypted_file_path = os.path.join(os.path.dirname(encrypted_file_path), original_file_name)
    
    # Desencriptar el archivo
    decrypt_file(
        encrypted_file_path=encrypted_file_path,
        master_key=request.user.password.encode(),
        encrypted_file_key=file_entry.encrypted_key,
        iv_or_nonce=file_entry.iv_or_nonce,
        entry_salt=file_entry.salt,
        algorithm=file_entry.algorithm,
        output_file_path=decrypted_file_path
    )

    # Abrir el archivo desencriptado y devolverlo como respuesta para descargar
    with open(decrypted_file_path, 'rb') as f:
        file_content = f.read()

    response = HttpResponse(file_content, content_type='application/octet-stream')
    response['Content-Disposition'] = f'attachment; filename={os.path.basename(decrypted_file_path)}'
    
    if os.path.exists(decrypted_file_path):
        os.remove(decrypted_file_path)

    return response


@login_required
def file_list(request):
    files = EncryptedFile.objects.filter(user=request.user)
    return render(request, 'files/file_list.html', {'files': files})

@login_required
def delete_file(request, file_id):
    file_entry = None  # Inicializa file_entry con None
    error_message = None  # Inicializa un mensaje de error vacío

    if request.method == 'POST':
        # Verificar si se proporciona la contraseña maestra
        master_password = request.POST.get('master_password')
        if master_password:
            # Obtener la entrada de la clave maestra del usuario
            master_key_entry = get_object_or_404(MasterKey, user=request.user)
            if master_key_entry.verify_master_key(master_password):
                # Obtener el archivo encriptado que se desea eliminar
                file_entry = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
                
                # Eliminar el archivo del sistema de archivos
                if os.path.exists(file_entry.file_path):
                    os.remove(file_entry.file_path)
                
                # Eliminar la entrada del archivo de la base de datos
                file_entry.delete()

                # Redirigir a la lista de archivos después de eliminar
                return redirect('list_files')
            else:
                error_message = "Master password incorrecta."
        else:
            error_message = "Debe ingresar una master password."

    # Si hay un error o no se ha eliminado el archivo, renderiza la página con el mensaje de error
    return render(request, 'files/delete_file.html', {'error_message': error_message, 'file_entry': file_entry})


@login_required
def delete_all_files(request):
    if request.method == "POST":
        master_password = request.POST.get('master_password')
        if master_password:
            # Verifica la contraseña maestra
            master_key_entry = get_object_or_404(MasterKey, user=request.user)
            if master_key_entry.verify_master_key(master_password):
                # Obtiene y elimina todos los archivos del usuario
                files = EncryptedFile.objects.filter(user=request.user)
                for file in files:
                    # Elimina el archivo del sistema de archivos si es necesario
                    if os.path.exists(file.file_path):
                        os.remove(file.file_path)
                    # Elimina la entrada de la base de datos
                    file.delete()
                return redirect('list_files')  # Redirige a la lista de archivos después de eliminar
        else:
            error_message = "Contraseña maestra incorrecta."

        # Renderiza la página con un mensaje de error si la contraseña es incorrecta
        return render(request, 'files/file_list.html', {'error_message': error_message})

    # Si no es un POST, redirige a la lista de archivos
    return redirect('list_files')


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


@login_required(login_url='login')
def settings_view(request):
    user_settings, created = UserSettings.objects.get_or_create(user=request.user)

    if created:
        messages.info(request, 'Se han creado tus configuraciones por defecto. Puedes ajustarlas a continuación.')

    if request.method == 'POST':
        form = SettingsForm(request.POST, instance=user_settings)
        if form.is_valid():
            form.save()
            messages.success(request, 'Configuraciones actualizadas correctamente.')
            return redirect('settings_view')
        else:
            messages.error(request, 'Hubo un error al actualizar las configuraciones.')
    else:
        form = SettingsForm(instance=user_settings)

    return render(request, 'ajustes.html', {'form': form})
