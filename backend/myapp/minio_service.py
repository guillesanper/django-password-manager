import os
import logging
from minio import Minio
from minio.error import S3Error
from django.conf import settings
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import datetime
import io

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
    
    def upload_file(self, file_data, object_name, metadata=None):
        """
        Subir archivo ya encriptado (primera capa) aplicando solo segunda capa (Fernet)
        """
        try:
            # Segunda capa: Encriptación del sistema con Fernet
            final_encrypted_data = self.system_fernet.encrypt(file_data)
            
            # Crear stream
            file_stream = io.BytesIO(final_encrypted_data)
            
            # Subir a MinIO con metadatos
            result = self.client.put_object(
                self.bucket_name,
                object_name,
                file_stream,
                len(final_encrypted_data),
                content_type='application/octet-stream',
                metadata=metadata or {}
            )
            
            audit_logger.info(f"File uploaded to MinIO: {object_name}")
            
            return {
                'success': True,
                'object_name': object_name,
                'etag': result.etag if hasattr(result, 'etag') else None
            }
            
        except S3Error as e:
            security_logger.error(f"MinIO error uploading file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Upload error: {e}")
            return {'success': False, 'error': f'Upload error: {str(e)}'}
    
    def download_file(self, object_name):
        """
        Descargar archivo y desencriptar solo segunda capa (Fernet)
        Retorna los datos con primera capa de encriptación intacta
        """
        try:
            # Obtener objeto encriptado
            response = self.client.get_object(self.bucket_name, object_name)
            encrypted_data = response.read()
            response.close()
            
            # Desencriptar segunda capa (sistema)
            try:
                first_layer_data = self.system_fernet.decrypt(encrypted_data)
            except Exception as e:
                security_logger.error(f"System decryption failed for {object_name}: {e}")
                return {'success': False, 'error': 'System decryption failed'}
            
            audit_logger.info(f"File downloaded from MinIO: {object_name}")
            
            return {
                'success': True,
                'data': first_layer_data  # Datos con solo primera capa de encriptación
            }
            
        except S3Error as e:
            if e.code == 'NoSuchKey':
                security_logger.error(f"File not found: {object_name}")
                return {'success': False, 'error': 'File not found in storage'}
            security_logger.error(f"MinIO error downloading file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Download error: {e}")
            return {'success': False, 'error': f'Download error: {str(e)}'}
    
    def delete_file(self, object_name):
        """Eliminar archivo de MinIO"""
        try:
            # Verificar que el archivo existe antes de intentar eliminarlo
            try:
                self.client.stat_object(self.bucket_name, object_name)
            except S3Error as e:
                if e.code == 'NoSuchKey':
                    audit_logger.info(f"File already deleted or not found: {object_name}")
                    return {'success': True, 'message': 'File already deleted'}
                raise e
            
            # Eliminar archivo
            self.client.remove_object(self.bucket_name, object_name)
            
            audit_logger.info(f"File deleted from MinIO: {object_name}")
            return {'success': True, 'message': 'File deleted successfully'}
            
        except S3Error as e:
            security_logger.error(f"Error deleting file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Delete error: {e}")
            return {'success': False, 'error': f'Delete error: {str(e)}'}
    
    def delete_user_files(self, user_id):
        """Eliminar todos los archivos de un usuario"""
        try:
            # Listar todos los objetos del usuario
            objects = self.client.list_objects(
                self.bucket_name, 
                prefix=f"user_{user_id}/", 
                recursive=True
            )
            
            deleted_count = 0
            errors = []
            
            for obj in objects:
                try:
                    self.client.remove_object(self.bucket_name, obj.object_name)
                    deleted_count += 1
                    audit_logger.info(f"File deleted in bulk operation: {obj.object_name}")
                except Exception as e:
                    error_msg = f"Error deleting {obj.object_name}: {str(e)}"
                    errors.append(error_msg)
                    security_logger.error(error_msg)
            
            if errors:
                return {
                    'success': False,
                    'message': f'{deleted_count} files deleted successfully',
                    'errors': errors,
                    'deleted_count': deleted_count
                }
            
            return {
                'success': True,
                'message': f'All files ({deleted_count}) deleted successfully',
                'deleted_count': deleted_count
            }
            
        except S3Error as e:
            security_logger.error(f"Error in bulk delete operation: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Bulk delete error: {e}")
            return {'success': False, 'error': f'Bulk delete error: {str(e)}'}
        
    def upload_file_simple(self, file_data, object_name, metadata=None):
        """
        Subir archivo sin encriptación Fernet (solo encryption_utils)
        """
        try:
            # Crear stream directamente con los datos encriptados
            file_stream = io.BytesIO(file_data)
            
            # Subir a MinIO con metadatos
            result = self.client.put_object(
                self.bucket_name,
                object_name,
                file_stream,
                len(file_data),
                content_type='application/octet-stream',
                metadata=metadata or {}
            )
            
            audit_logger.info(f"File uploaded to MinIO (simple): {object_name}")
            
            return {
                'success': True,
                'object_name': object_name,
                'etag': result.etag if hasattr(result, 'etag') else None
            }
            
        except S3Error as e:
            security_logger.error(f"MinIO error uploading file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Upload error: {e}")
            return {'success': False, 'error': f'Upload error: {str(e)}'}
    
    def download_file_simple(self, object_name):
        """
        Descargar archivo sin desencriptación Fernet (solo retorna datos encriptados por encryption_utils)
        """
        try:
            # Obtener objeto directamente
            response = self.client.get_object(self.bucket_name, object_name)
            encrypted_data = response.read()
            response.close()
            
            audit_logger.info(f"File downloaded from MinIO (simple): {object_name}")
            
            return {
                'success': True,
                'data': encrypted_data  # Datos encriptados solo con encryption_utils
            }
            
        except S3Error as e:
            if e.code == 'NoSuchKey':
                security_logger.error(f"File not found: {object_name}")
                return {'success': False, 'error': 'File not found in storage'}
            security_logger.error(f"MinIO error downloading file: {e}")
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            security_logger.error(f"Download error: {e}")
            return {'success': False, 'error': f'Download error: {str(e)}'}
    
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
                    
                    file_info = {
                        'object_name': obj.object_name.split('/')[-1],  # Solo el nombre
                        'full_path': obj.object_name,
                        'size': obj.size,
                        'last_modified': obj.last_modified.isoformat() if obj.last_modified else None,
                        'etag': obj.etag,
                        'encryption_algorithm': metadata.get('encryption_algorithm', 'Unknown'),
                        'original_filename': metadata.get('original_filename', obj.object_name.split('/')[-1]),
                        'upload_timestamp': metadata.get('upload_timestamp'),
                        'file_size': metadata.get('file_size')
                    }
                    
                    files.append(file_info)
                    
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
    
    def get_file_info(self, object_name):
        """Obtener información detallada de un archivo sin descargarlo"""
        try:
            stat = self.client.stat_object(self.bucket_name, object_name)
            
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
            if e.code == 'NoSuchKey':
                return {'success': False, 'error': 'File not found'}
            return {'success': False, 'error': f'Storage error: {str(e)}'}
        except Exception as e:
            return {'success': False, 'error': f'Info error: {str(e)}'}
    
    def get_user_storage_stats(self, user_id):
        """Obtener estadísticas de almacenamiento del usuario"""
        try:
            objects = self.client.list_objects(
                self.bucket_name, 
                prefix=f"user_{user_id}/", 
                recursive=True
            )
            
            total_size = 0
            total_files = 0
            algorithms = []
            
            for obj in objects:
                total_files += 1
                total_size += obj.size
                
                try:
                    stat = self.client.stat_object(self.bucket_name, obj.object_name)
                    if stat.metadata:
                        algorithm = stat.metadata.get('encryption_algorithm', 'Unknown')
                        algorithms.append(algorithm)
                except:
                    algorithms.append('Unknown')
            
            return {
                'success': True,
                'stats': {
                    'total_files': total_files,
                    'total_size': total_size,
                    'algorithms': algorithms
                }
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}

# Instancia global
enhanced_minio_service = MinIOService()