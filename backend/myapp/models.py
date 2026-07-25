from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password


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
    # Esquema zero-knowledge (Fase 2). Los campos v1 en claro (website/username/
    # encrypted_password/encryption_algorithm/salt/iv_or_nonce/encrypted_key) se purgaron en el
    # paso 26: el sitio, el usuario y la contraseña viajan cifrados DENTRO de `ciphertext`.
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    vault = models.ForeignKey('Vault', on_delete=models.SET_NULL, null=True, blank=True, related_name='passwords')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # crypto_version 2 = blob AEAD cifrado en cliente (único esquema tras la purga del paso 26).
    crypto_version = models.PositiveSmallIntegerField(default=1)
    # AES-256-GCM(VaultKey, plaintext): nonce||ciphertext||tag en base64. Opaco para el servidor.
    ciphertext = models.TextField(null=True, blank=True)
    # Identidad estable generada por el cliente (UUID), parte de la AAD. `unique` impide que un
    # atacante con escritura en BD copie a la vez ciphertext+client_id de otra fila (anti-swap).
    client_id = models.UUIDField(null=True, blank=True, unique=True)

    def __str__(self):
        return f"PasswordEntry {self.id} (user {self.user_id})"


class UserCrypto(models.Model):
    """Material criptográfico zero-knowledge del usuario (Fase 2, §8 de la auditoría).

    El servidor NUNCA ve la contraseña maestra, la Master Key (MK), la EncKey ni la VaultKey.
    Sólo guarda material opaco:
      - kdf_salt / kdf_params: para que el cliente rederive MK = Argon2id(master_password, salt).
      - auth_key_hash: Argon2id(AuthKey) vía PASSWORD_HASHERS. Verifica pero no reconstruye la MK.
      - wrapped_vault_key: AES-256-GCM(EncKey, VaultKey). Sólo el cliente puede desenvolverla.

    Sustituyó a MasterKey (C1/C2), purgado en el paso 26.
    """
    CURRENT_CRYPTO_VERSION = 2

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='crypto')
    # Sal por usuario (no global) para Argon2id(master_password) en el cliente. Base64.
    kdf_salt = models.CharField(max_length=64)
    # Parámetros de derivación acordados con el cliente: {"algo","m","t","p","hashLen","version"}.
    kdf_params = models.JSONField(default=dict)
    # Argon2id(AuthKey) vía make_password/PASSWORD_HASHERS (Argon2 primero, paso 14).
    auth_key_hash = models.CharField(max_length=255)
    # AES-256-GCM(EncKey, VaultKey): nonce||ciphertext||tag en base64. Opaco para el servidor.
    wrapped_vault_key = models.TextField()
    crypto_version = models.PositiveSmallIntegerField(default=CURRENT_CRYPTO_VERSION)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_auth_key(self, auth_key_b64):
        """Guarda Argon2id(AuthKey). auth_key_b64 es la AuthKey derivada en el cliente, en base64."""
        self.auth_key_hash = make_password(auth_key_b64)

    def verify_auth_key(self, auth_key_b64):
        """Verifica la AuthKey contra el hash almacenado, en tiempo constante (check_password)."""
        return check_password(auth_key_b64, self.auth_key_hash)

    def __str__(self):
        return f"UserCrypto de {self.user.username} (v{self.crypto_version})"


class EncryptedFile(models.Model):
    # Esquema zero-knowledge (Fase 2). Los campos v1 en claro (title/salt/iv_or_nonce/algorithm/
    # encrypted_key) se purgaron en el paso 26; el FileField local legado `encrypted_file` se purgó
    # en el paso 28 (migración 0026). El título, los metadatos y la clave de fichero van cifrados
    # DENTRO de `ciphertext`; en v2 el objeto vive en MinIO (`file_path`).
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='encrypted_files')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file_path = models.CharField(max_length=255, blank=True, null=True)  # Ruta del objeto en MinIO
    updated_at = models.DateTimeField(auto_now=True)

    # crypto_version 2 = cifrado por chunks en cliente (único esquema tras la purga del paso 26).
    crypto_version = models.PositiveSmallIntegerField(default=1)
    # Metadatos y clave de fichero envueltos por el cliente (nonce||ciphertext||tag base64). Opaco.
    ciphertext = models.TextField(null=True, blank=True)
    # Identidad estable del cliente (UUID), parte de la AAD del fichero. `unique` = anti-swap.
    client_id = models.UUIDField(null=True, blank=True, unique=True)

    def __str__(self):
        return f"EncryptedFile {self.id} (user {self.user_id})"

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

    # --- Fase 2 (zero-knowledge) — material de subclave por bóveda privada (paso 24) ---
    # Espeja a UserCrypto pero con la CONTRASEÑA DEL VAULT como secreto (segundo factor: la
    # maestra por sí sola no abre una bóveda privada). El servidor nunca ve esa contraseña.
    #   SubMK   = Argon2id(vault_password, sub_kdf_salt) → SubAuthKey=HKDF(SubMK,"auth"),
    #                                                       SubEncKey=HKDF(SubMK,"enc")
    #   wrapped_vault_subkey = AES-256-GCM(SubEncKey, VaultSubKey)  (opaco para el servidor)
    # vault_crypto_version 1 = bóveda legada (vault_password_hash); 2 = subclave zero-knowledge.
    sub_kdf_salt = models.CharField(max_length=64, blank=True, null=True)
    sub_kdf_params = models.JSONField(default=dict, blank=True)
    # Argon2id(SubAuthKey) vía make_password/PASSWORD_HASHERS. Verifica posesión, no reconstruye.
    sub_auth_key_hash = models.CharField(max_length=255, blank=True, null=True)
    wrapped_vault_subkey = models.TextField(blank=True, null=True)
    vault_crypto_version = models.PositiveSmallIntegerField(default=1)

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
    
    # --- Subclave zero-knowledge (paso 24) ---

    def set_sub_auth_key(self, sub_auth_key_b64):
        """Guarda Argon2id(SubAuthKey). sub_auth_key_b64 es la SubAuthKey derivada en el cliente.

        Espeja a UserCrypto.set_auth_key. No se guarda la contraseña del vault ni la SubEncKey:
        el servidor sólo puede verificar posesión, nunca abrir la bóveda.
        """
        self.sub_auth_key_hash = make_password(sub_auth_key_b64)

    def verify_sub_auth_key(self, sub_auth_key_b64):
        """Verifica la SubAuthKey contra el hash almacenado, en tiempo constante (check_password)."""
        if not self.is_private or not self.sub_auth_key_hash:
            return False
        return check_password(sub_auth_key_b64, self.sub_auth_key_hash)

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