from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

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
    algorithm_key = decrypt_with_master_key(encrypted_key, master_key, entry_salt)
    encrypted_password = urlsafe_b64decode(encrypted_password)
    
    if algorithm == "AES":
        iv = urlsafe_b64decode(iv_or_nonce)
        cipher = Cipher(algorithms.AES(algorithm_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
        
        try:
            return decrypted_password.decode('utf-8')
        except UnicodeDecodeError as e:
            print(f"UnicodeDecodeError en decodificación: {e}")
            raise ValueError(f"Error en la decodificación: {e}")
    
    elif algorithm == "ChaCha20":
        nonce = urlsafe_b64decode(iv_or_nonce)
        cipher = Cipher(algorithms.ChaCha20(algorithm_key, nonce), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
        try:
            return decrypted_password.decode('utf-8')
        except UnicodeDecodeError as e:
            print(f"UnicodeDecodeError en decodificación: {e}")
            raise ValueError(f"Error en la decodificación: {e}")
    
    raise ValueError("Algoritmo de encriptación desconocido")
