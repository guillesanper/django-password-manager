from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.utils.crypto import get_random_string

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os


# Create your models here.
class UserSettings(models.Model):
    THEME_CHOICES = [
        ('light', 'Claro'),
        ('dark', 'Oscuro'),
        ('pink', 'Rosa'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    theme = models.CharField(max_length=10, choices=THEME_CHOICES, default='light')
    require_password_modify = models.BooleanField(default=True)
    require_password_delete = models.BooleanField(default=True)
    notifications = models.CharField(max_length=10, choices=[('enabled', 'Activadas'), ('disabled', 'Desactivadas')], default='enabled')

    def __str__(self):
        return f"Configuraciones de {self.user.username}"

class PasswordEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    vault = models.ForeignKey('Vault', on_delete=models.SET_NULL, null=True, blank=True, related_name='passwords')
    website = models.CharField(max_length=255)
    username = models.CharField(max_length=255)
    encrypted_password = models.TextField()
    encryption_algorithm = models.CharField(max_length=50)
    salt = models.CharField(max_length=32, default=get_random_string(32))  # Sal aleatoria asociada a la entrada
    iv_or_nonce = models.TextField(max_length=32)  # Almacena el IV o nonce usado
    encrypted_key = models.TextField(max_length=32)  # Clave encriptada
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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


class EncryptedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='encrypted_files')
    title = models.CharField(max_length=255)
    encrypted_file = models.FileField(upload_to='encrypted_files/')
    salt = models.CharField(max_length=64)
    iv_or_nonce = models.CharField(max_length=64)
    algorithm = models.CharField(max_length=10, default='AES')
    encrypted_key = models.TextField(max_length=32)  # Clave encriptada
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file_path = models.CharField(max_length=255, blank=True, null=True)  # Ruta del archivo
    updated_at = models.DateTimeField(auto_now=True)


    def __str__(self):
        return self.title
    
class ActivityLog(models.Model):
    ACTIVITY_TYPES = [
        ('password_created', 'Contraseña Creada'),
        ('password_updated', 'Contraseña Actualizada'),
        ('password_deleted', 'Contraseña Eliminada'),
        ('password_viewed', 'Contraseña Visualizada'),
        ('file_uploaded', 'Archivo Subido'),
        ('file_downloaded', 'Archivo Descargado'),
        ('file_deleted', 'Archivo Eliminado'),
        ('login', 'Inicio de Sesión'),
        ('logout', 'Cierre de Sesión'),
        ('settings_updated', 'Configuración Actualizada'),
        ('master_key_created', 'Clave Maestra Creada'),
        ('master_key_verified', 'Clave Maestra Verificada'),
        ('security_analysis', 'Análisis de Seguridad'),
        ('vault_created', 'Vault Creado'),
        ('vault_updated', 'Vault Actualizado'),
        ('vault_deleted', 'Vault Eliminado'),
        ('vault_unlocked', 'Vault Desbloqueado'),
        ('password_moved', 'Contraseña Movida'),
    ]
    
    SEVERITY_LEVELS = [
        ('success', 'Éxito'),
        ('info', 'Información'),
        ('warning', 'Advertencia'),
        ('error', 'Error'),
        ('critical', 'Crítico'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=30, choices=ACTIVITY_TYPES)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='info')
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Para relacionar con otros objetos
    related_object_type = models.CharField(max_length=50, blank=True, null=True)
    related_object_id = models.PositiveIntegerField(blank=True, null=True)
    
    # Información adicional de contexto
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['user', 'activity_type']),
            models.Index(fields=['severity', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.title} ({self.timestamp.strftime('%Y-%m-%d %H:%M')})"

class Vault(models.Model):
    """Modelo para vaults/carpetas de contraseñas"""
    VAULT_COLORS = [
        ('blue', 'Azul'),
        ('green', 'Verde'),
        ('red', 'Rojo'),
        ('yellow', 'Amarillo'),
        ('purple', 'Morado'),
        ('orange', 'Naranja'),
        ('pink', 'Rosa'),
        ('gray', 'Gris'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='vaults')
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    color = models.CharField(max_length=10, choices=VAULT_COLORS, default='blue')
    is_private = models.BooleanField(default=False)
    
    # Para vaults privados - contraseña adicional
    vault_password_hash = models.CharField(max_length=255, blank=True, null=True)
    vault_salt = models.CharField(max_length=32, blank=True, null=True)
    
    # Metadatos
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['user', 'name']),
            models.Index(fields=['user', 'is_private']),
        ]
        unique_together = ['user', 'name']  # Nombres únicos por usuario
    
    def __str__(self):
        privacy_indicator = "🔒" if self.is_private else "📁"
        return f"{privacy_indicator} {self.name} ({self.user.username})"
    
    def set_vault_password(self, password):
        """Establece la contraseña del vault (solo para vaults privados)"""
        if not self.is_private:
            raise ValueError("Solo los vaults privados pueden tener contraseña")
        
        # Generar salt único para este vault
        self.vault_salt = get_random_string(32)
        
        # Derivar y hashear la contraseña del vault
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import base64
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.vault_salt.encode(),
            iterations=100000,
        )
        derived_key = kdf.derive(password.encode())
        self.vault_password_hash = base64.b64encode(derived_key).decode('utf-8')
    
    def verify_vault_password(self, password):
        """Verifica la contraseña del vault"""
        if not self.is_private or not self.vault_password_hash:
            return True  # Vault público o sin contraseña
        
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            import base64
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.vault_salt.encode(),
                iterations=100000,
            )
            derived_key = kdf.derive(password.encode())
            expected_hash = base64.b64encode(derived_key).decode('utf-8')
            
            return expected_hash == self.vault_password_hash
        except Exception:
            return False
    
    def get_password_count(self):
        """Obtiene el número de contraseñas en este vault"""
        return self.passwords.count()
    
class SecurityEvent(models.Model):
    """Modelo para eventos de seguridad críticos"""
    EVENT_TYPES = [
        ('failed_login', 'Intento de Login Fallido'),
        ('multiple_failed_logins', 'Múltiples Intentos Fallidos'),
        ('master_key_failed', 'Fallo de Clave Maestra'),
        ('suspicious_activity', 'Actividad Sospechosa'),
        ('decryption_failure', 'Error de Desencriptación'),
        ('unauthorized_access', 'Acceso No Autorizado'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    event_type = models.CharField(max_length=30, choices=EVENT_TYPES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    additional_data = models.JSONField(default=dict, blank=True)  # Para datos extra
    timestamp = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['resolved', 'timestamp']),
        ]
    
    def __str__(self):
        username = self.user.username if self.user else 'Unknown'
        return f"{self.event_type} - {username} ({self.timestamp.strftime('%Y-%m-%d %H:%M')})"