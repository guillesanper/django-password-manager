from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.utils.crypto import get_random_string

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os


# Create your models here.
    
class PasswordEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    website = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    encrypted_password = models.TextField()
    encryption_algorithm = models.CharField(max_length=50)
    salt = models.CharField(max_length=32, default=get_random_string(32))  # Sal aleatoria asociada a la entrada
    iv_or_nonce = models.TextField()  # Almacena el IV o nonce usado
    encrypted_key = models.TextField()  # Clave encriptada

    def __str__(self):
        return f"{self.website} ({self.username})"
    

class MasterKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    hashed_key = models.CharField(max_length=255)  # Hash de la master key
    salt = models.CharField(max_length=32, default=get_random_string(32))  # Sal para derivar la master key

    def derive_master_key(self, raw_key):
        # Deriva la master key usando PBKDF2 y la sal almacenada
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt.encode(),
            iterations=100000,
        )
        derived_key = kdf.derive(raw_key.encode())

        # Verifica si la clave tiene el tamaño correcto
        if len(derived_key) not in [16, 24, 32]:
            return None

        return derived_key

    def set_master_key(self, raw_key):
        # Deriva la master key
        master_key = self.derive_master_key(raw_key)
        master_key_str = base64.b64encode(master_key).decode('utf-8')

        self.hashed_key = master_key_str  # Almacena la clave derivada sin hashear de nuevo
        self.save()
        return master_key  # Devuelve la master key derivada

    def verify_master_key(self, raw_key):
        derived_key = self.derive_master_key(raw_key)
        derived_key_str = base64.b64encode(derived_key).decode('utf-8')

        print(f"Derived Key: {derived_key_str}")
        print(f"Stored Hashed Key: {self.hashed_key}")

        # Verifica si la clave derivada coincide con la clave almacenada
        return derived_key_str == self.hashed_key