import os
import logging
from minio import Minio
from minio.error import S3Error
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import io
import secrets
import json
from datetime import datetime

audit_logger = logging.getLogger('audit')
security_logger = logging.getLogger('security')

class MinIOService:
    def __init__(self):
        self.client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_USE_SSL
        )
        self.bucket_name = settings.MINIO_BUCKET_NAME
        self.system_fernet = Fernet(self._get_system_encryption_key())
        
        # Crear bucket si no existe
        self._ensure_bucket_exists()
    
    def _get_system_encryption_key(self):
        """Obtener clave de encriptación del sistema desde variable de entorno"""
        key = os.getenv('ENCRYPTION_KEY')
        if not key:
            # Generar nueva clave si no existe (solo para desarrollo)
            key = Fernet.generate_key()
            security_logger.warning("Generated new system encryption key - store securely!")
            return key
        
        # Si la clave no está en formato Fernet, derivarla
        if len(key.encode()) != 44:  # Fernet keys are 44 characters when base64 encoded
            # Derivar clave Fernet desde la clave proporcionada
            salt = b"minio_system_salt_2024"  # Salt fijo para el sistema
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            derived_key = kdf.derive(key.encode())
            return urlsafe_b64encode(derived_key)
        
        return key.encode() if isinstance(key, str) else key
    
    def _ensure_bucket_exists(self):
        """Asegurar que el bucket existe"""
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
                security_logger.info(f"Created MinIO bucket: {self.bucket_name}")
        except S3Error as e:
            security_logger.error(f"Error creating bucket: {e}")
    
    def _derive_user_key(self, master_key_bytes, user_salt):
        """Derivar clave de usuario específica desde la master key"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=user_salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(master_key_bytes)
    
    def _encrypt_with_user_key(self, data, user_key, algorithm="AES"):
        """Encriptar datos con la clave del usuario (primera capa)"""
        if algorithm == "AES":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(user_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            return iv + encrypted_data  # IV + datos encriptados
            
        elif algorithm == "ChaCha20":
            nonce = os.urandom(16)
            cipher = Cipher(algorithms.ChaCha20(user_key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            return nonce + encrypted_data  # Nonce + datos encriptados
        
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
    
    def _decrypt_with_user_key(self, encrypted_data, user_key, algorithm="AES"):
        """Desencriptar datos con la clave del usuario (primera capa)"""
        if algorithm == "AES":
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.AES(user_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
            
        elif algorithm == "ChaCha20":
            nonce = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            cipher = Cipher(algorithms.ChaCha20(user_key, nonce), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        
        else:
            raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
    
    def upload_encrypted_file(self, file_data, object_name, user_id, master_key_bytes, 
                            user_algorithm="AES", enable_double_encryption=True):
        """
        Subir archivo con encriptación en capas:
        1. Primera capa: Encriptación del usuario con su master key
        2. Segunda capa: Encriptación del sistema (opcional)
        """
        try:
            # Generar salt único para este archivo
            user_salt = os.urandom(16)
            
            # Derivar clave del usuario desde su master key
            user_key = self._derive_user_key(master_key_bytes, user_salt)
            
            # Primera capa: Encriptar con la clave del usuario
            first_layer_encrypted = self._encrypt_with_user_key(
                file_data, user_key, user_algorithm
            )
            
            # Segunda capa: Encriptación del sistema (opcional)
            if enable_double_encryption:
                final_encrypted_data = self.system_fernet.encrypt(first_layer_encrypted)
            else:
                final_encrypted_data = first_layer_encrypted
            
            # Metadatos del archivo
            metadata = {
                'user_id': str(user_id),
                'encryption_algorithm': user_algorithm,
                'double_encrypted': str(enable_double_encryption),
                'user_salt': urlsafe_b64encode(user_salt).decode(),
                'upload_timestamp': datetime.utcnow().isoformat(),
                'original_filename': object_name,
                'file_size': str(len(file_data))
            }
            
            # Crear stream
            file_stream = io.BytesIO(final_encrypted_data)
            
            # Subir a MinIO con metadatos
            self.client.put_object(
                self.bucket_name,
                f"user_{user_id}/{object_name}",
                file_stream,
                len(final_encrypted_data),
                content_type='application/octet-stream',
                metadata=metadata
            )
            
            audit_logger.info(
                f"Double-encrypted file uploaded: user_{user_id}/{object_name}, "
                f"algorithm={user_algorithm}, double_encryption={enable_double_encryption}"
            )
            
            return {
                'success': True,
                'metadata': metadata,
                'object_path': f"user_{user_id}/{object_name}"
            }
            
        except S3Error as e:
            security_logger.error(f"MinIO error uploading file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Encryption error: {e}")
            return {'success': False, 'error': f'Encryption error: {str(e)}'}
    
    def download_encrypted_file(self, object_name, user_id, master_key_bytes):
        """
        Descargar y desencriptar archivo en capas:
        1. Obtener metadatos del archivo
        2. Desencriptar segunda capa (sistema) si aplica
        3. Desencriptar primera capa (usuario) con master key
        """
        try:
            object_path = f"user_{user_id}/{object_name}"
            
            # Obtener objeto y metadatos
            response = self.client.get_object(self.bucket_name, object_path)
            encrypted_data = response.read()
            
            # Obtener metadatos del archivo
            stat = self.client.stat_object(self.bucket_name, object_path)
            metadata = stat.metadata
            
            if not metadata:
                security_logger.error(f"No metadata found for file: {object_path}")
                return {'success': False, 'error': 'File metadata not found'}
            
            # Extraer información de metadatos
            user_algorithm = metadata.get('encryption_algorithm', 'AES')
            is_double_encrypted = metadata.get('double_encrypted', 'True') == 'True'
            user_salt = urlsafe_b64decode(metadata.get('user_salt', '').encode())
            
            # Segunda capa: Desencriptar con clave del sistema si aplica
            if is_double_encrypted:
                try:
                    first_layer_data = self.system_fernet.decrypt(encrypted_data)
                except Exception as e:
                    security_logger.error(f"System decryption failed for {object_path}: {e}")
                    return {'success': False, 'error': 'System decryption failed'}
            else:
                first_layer_data = encrypted_data
            
            # Primera capa: Desencriptar con clave del usuario
            user_key = self._derive_user_key(master_key_bytes, user_salt)
            
            try:
                decrypted_data = self._decrypt_with_user_key(
                    first_layer_data, user_key, user_algorithm
                )
            except Exception as e:
                security_logger.error(f"User decryption failed for {object_path}: {e}")
                return {'success': False, 'error': 'User decryption failed - invalid master key'}
            
            audit_logger.info(f"Double-encrypted file downloaded: {object_path}")
            
            return {
                'success': True,
                'data': decrypted_data,
                'metadata': {
                    'original_filename': metadata.get('original_filename', object_name),
                    'algorithm': user_algorithm,
                    'upload_timestamp': metadata.get('upload_timestamp'),
                    'file_size': metadata.get('file_size')
                }
            }
            
        except S3Error as e:
            security_logger.error(f"MinIO error downloading file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Download error: {e}")
            return {'success': False, 'error': f'Download error: {str(e)}'}
    
    def delete_file(self, object_name, user_id):
        """Eliminar archivo de MinIO con auditoría mejorada"""
        try:
            object_path = f"user_{user_id}/{object_name}"
            
            # Obtener metadatos antes de eliminar para auditoría
            try:
                stat = self.client.stat_object(self.bucket_name, object_path)
                metadata = stat.metadata
                original_filename = metadata.get('original_filename', object_name)
            except:
                original_filename = object_name
            
            self.client.remove_object(self.bucket_name, object_path)
            
            audit_logger.info(
                f"File deleted: {object_path}, original_name={original_filename}"
            )
            return {'success': True, 'message': 'File deleted successfully'}
            
        except S3Error as e:
            security_logger.error(f"Error deleting file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Delete error: {e}")
            return {'success': False, 'error': f'Delete error: {str(e)}'}
    
    def list_user_files(self, user_id):
        """Listar archivos del usuario con información de metadatos"""
        try:
            objects = self.client.list_objects(
                self.bucket_name, 
                prefix=f"user_{user_id}/", 
                recursive=True
            )
            
            files = []
            for obj in objects:
                try:
                    # Obtener metadatos
                    stat = self.client.stat_object(self.bucket_name, obj.object_name)
                    metadata = stat.metadata if stat.metadata else {}
                    
                    files.append({
                        'object_name': obj.object_name.split('/')[-1],  # Solo el nombre
                        'full_path': obj.object_name,
                        'size': obj.size,
                        'last_modified': obj.last_modified.isoformat() if obj.last_modified else None,
                        'encryption_algorithm': metadata.get('encryption_algorithm', 'Unknown'),
                        'double_encrypted': metadata.get('double_encrypted', 'Unknown'),
                        'original_filename': metadata.get('original_filename', obj.object_name),
                        'upload_timestamp': metadata.get('upload_timestamp')
                    })
                except Exception as e:
                    # Si hay error obteniendo metadatos, incluir información básica
                    files.append({
                        'object_name': obj.object_name.split('/')[-1],
                        'full_path': obj.object_name,
                        'size': obj.size,
                        'last_modified': obj.last_modified.isoformat() if obj.last_modified else None,
                        'error': f'Metadata error: {str(e)}'
                    })
            
            return {'success': True, 'files': files}
            
        except S3Error as e:
            security_logger.error(f"Error listing files for user {user_id}: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"List files error: {e}")
            return {'success': False, 'error': f'List error: {str(e)}'}
    
    def get_file_info(self, object_name, user_id):
        """Obtener información detallada de un archivo sin descargarlo"""
        try:
            object_path = f"user_{user_id}/{object_name}"
            stat = self.client.stat_object(self.bucket_name, object_path)
            
            return {
                'success': True,
                'info': {
                    'size': stat.size,
                    'last_modified': stat.last_modified.isoformat() if stat.last_modified else None,
                    'etag': stat.etag,
                    'metadata': stat.metadata if stat.metadata else {}
                }
            }
        except S3Error as e:
            return {'success': False, 'error': f'File not found: {str(e)}'}
        except Exception as e:
            return {'success': False, 'error': f'Info error: {str(e)}'}

# Instancia global
enhanced_minio_service = MinIOService()