import logging
from minio import Minio
from minio.error import S3Error
from minio.sse import SseS3
from django.conf import settings
import io

audit_logger = logging.getLogger('audit')
security_logger = logging.getLogger('security')

# ==========================================
# SERVICIO MinIO (Fase 2, zero-knowledge)
# ==========================================
#
# El contenido llega YA cifrado desde el cliente (crypto.ts::encryptFile, por chunks bajo una
# FileKey envuelta en la VaultKey). El servidor guarda un blob opaco: NUNCA ve texto claro.
#
# Paso 28: se retiró la capa Fernet de aplicación (era redundante sobre el cifrado de cliente y
# sostenía M2 —clave Fernet efímera por proceso—). El cifrado at-rest lo aporta MinIO vía SSE-S3
# (tajo B), gestionado por la infraestructura, no por este proceso.

class MinIOService:
    def __init__(self):
        self.client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_USE_SSL
        )
        self.bucket_name = settings.MINIO_BUCKET_NAME

        # Crear bucket si no existe
        self._ensure_bucket_exists()

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
        Subir el blob ya cifrado en cliente. El servidor no lo interpreta ni le aplica ninguna
        capa de aplicación; el cifrado at-rest lo aporta MinIO (SSE-S3).
        """
        try:
            file_stream = io.BytesIO(file_data)

            # Subir a MinIO con metadatos. sse=SseS3() → cifrado at-rest con el KMS local de
            # MinIO (defensa en profundidad sobre el ciphertext de cliente; sustituye a Fernet).
            result = self.client.put_object(
                self.bucket_name,
                object_name,
                file_stream,
                len(file_data),
                content_type='application/octet-stream',
                metadata=metadata or {},
                sse=SseS3()
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
        Descargar el blob tal cual (MinIO deshace la SSE-S3 de forma transparente). El cliente lo
        descifra con la FileKey; el servidor devuelve el ciphertext de cliente intacto.
        """
        try:
            response = self.client.get_object(self.bucket_name, object_name)
            data = response.read()
            response.close()

            audit_logger.info(f"File downloaded from MinIO: {object_name}")

            return {
                'success': True,
                'data': data  # Ciphertext de cliente, opaco para el servidor
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

            for obj in objects:
                total_files += 1
                total_size += obj.size

            return {
                'success': True,
                'stats': {
                    'total_files': total_files,
                    'total_size': total_size
                }
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

# Instancia global
enhanced_minio_service = MinIOService()
