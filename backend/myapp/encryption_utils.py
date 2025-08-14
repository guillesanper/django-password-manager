from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import string
import secrets

def derive_key_from_master_key(master_key, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_key)

def encrypt_with_master_key(algorithm_key, master_key, salt):
    key = derive_key_from_master_key(master_key, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(algorithm_key) + encryptor.finalize()
    return urlsafe_b64encode(iv + encrypted_key).decode()

def decrypt_with_master_key(encrypted_key, master_key, salt):
    encrypted_key = urlsafe_b64decode(encrypted_key)
    iv = encrypted_key[:16]
    encrypted_key = encrypted_key[16:]
    key = derive_key_from_master_key(master_key, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key) + decryptor.finalize()

def encrypt_password(password, master_key, algorithm="AES"):
    algorithm_key = os.urandom(32) if algorithm in ["AES", "ChaCha20"] else os.urandom(16)
    salt = os.urandom(16)  # Generar una salt única para esta entrada
    encrypted_key = encrypt_with_master_key(algorithm_key, master_key, salt)
    
    if algorithm == "AES":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(algorithm_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_password = encryptor.update(password.encode()) + encryptor.finalize()
        return urlsafe_b64encode(encrypted_password).decode(), encrypted_key, urlsafe_b64encode(iv).decode(), urlsafe_b64encode(salt).decode()

    elif algorithm == "ChaCha20":
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(algorithm_key, nonce), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_password = encryptor.update(password.encode())
        return urlsafe_b64encode(encrypted_password).decode(), encrypted_key, urlsafe_b64encode(nonce).decode(), urlsafe_b64encode(salt).decode()

def decrypt_password(encrypted_password, encrypted_key, iv_or_nonce, master_key, entry_salt, algorithm="AES"):
    algorithm_key = decrypt_with_master_key(encrypted_key, master_key, urlsafe_b64decode(entry_salt))
    
    if algorithm == "AES":
        cipher = Cipher(algorithms.AES(algorithm_key), modes.CFB(urlsafe_b64decode(iv_or_nonce)), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(urlsafe_b64decode(encrypted_password)) + decryptor.finalize()
        
    elif algorithm == "ChaCha20":
        cipher = Cipher(algorithms.ChaCha20(algorithm_key, urlsafe_b64decode(iv_or_nonce)), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(urlsafe_b64decode(encrypted_password)) + decryptor.finalize()
        
    else:
        raise ValueError("Algoritmo de encriptación desconocido")

    try:
        return decrypted_password
    except UnicodeDecodeError as e:
        print(f"UnicodeDecodeError en decodificación: {e}")
        raise ValueError(f"Error en la decodificación: {e}")


def generate_passwords(ammount:int,length:int,symbols:bool,uppercase:bool):
    passwords = []
    for _ in range(ammount):
        combination = string.ascii_lowercase +string.digits

        if symbols:
            combination += string.punctuation
        
        if uppercase:
            combination += string.ascii_uppercase

        combination_length = len(combination)
        password = ''
        for _ in range(length):
            password += combination[secrets.randbelow(combination_length)]

        passwords.append(password)

    return passwords



# Función para encriptar archivos
def encrypt_file(file_path: str, master_key: bytes, algorithm="AES"):
    file_key = os.urandom(32) if algorithm in ["AES", "ChaCha20"] else os.urandom(16)
    salt = os.urandom(16)

    # Leer el archivo
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Encriptar file_key con la master_key
    encrypted_file_key = encrypt_with_master_key(file_key, master_key, salt)
    
    # Crear el cifrado adecuado en función del algoritmo
    if algorithm == "AES":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(file_key), modes.CFB(iv), backend=default_backend())
    elif algorithm == "ChaCha20":
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.ChaCha20(file_key, nonce), mode=None, backend=default_backend())
    else:
        raise ValueError("Unknown encryption algorithm")
    
    # Encriptar los datos
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # Guardar el archivo encriptado
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)

    # Devolver los datos necesarios para la desencriptación
    if algorithm == "AES":
        return encrypted_file_key, urlsafe_b64encode(iv).decode(), urlsafe_b64encode(salt).decode()
    elif algorithm == "ChaCha20":
        return encrypted_file_key, urlsafe_b64encode(nonce).decode(), urlsafe_b64encode(salt).decode()

# return filepath

# Función para desencriptar archivos 

def decrypt_file(encrypted_file_path: str, master_key: bytes, encrypted_file_key: str, iv_or_nonce: str, entry_salt: str, algorithm="AES", output_file_path: str = None) -> None:
    # Leer los datos encriptados del archivo
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    # Desencriptar la clave del archivo usando la clave maestra
    file_key = decrypt_with_master_key(
        encrypted_file_key, 
        master_key, 
        urlsafe_b64decode(entry_salt)
    )

    # Configurar el cifrado con el algoritmo adecuado
    if algorithm == "AES":
        iv = urlsafe_b64decode(iv_or_nonce)
        cipher = Cipher(
            algorithms.AES(file_key), 
            modes.CFB(iv), 
            backend=default_backend()
        )
    elif algorithm == "ChaCha20":
        nonce = urlsafe_b64decode(iv_or_nonce)
        cipher = Cipher(
            algorithms.ChaCha20(file_key, nonce), 
            mode=None, 
            backend=default_backend()
        )
    else:
        raise ValueError("Unknown encryption algorithm")

    # Crear un desencriptador y desencriptar los datos
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Si no se especifica la ruta de salida, reemplazar la extensión .enc
    if output_file_path is None:
        output_file_path = encrypted_file_path.replace(".enc", "")

    # Guardar los datos desencriptados en un nuevo archivo
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)
    
    print(f"Archivo desencriptado, contenido: {decrypted_data}")

 