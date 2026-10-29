from django.core.management.base import BaseCommand
from minio.error import S3Error
import sys
import os

class Command(BaseCommand):
    help = 'Setup MinIO buckets and policies'

    def handle(self, *args, **options):
        try:
            # Import aquí para evitar problemas de configuración
            from myapp.minio_service import enhanced_minio_service as minio_service

            # Verificar conexión
            self.stdout.write('Verificando conexión a MinIO...')

            # Intentar listar buckets para verificar conexión
            try:
                buckets = minio_service.client.list_buckets()
                self.stdout.write(
                    self.style.SUCCESS('Conexión a MinIO exitosa')
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error conectando a MinIO: {e}')
                )
                self.stdout.write(
                    self.style.ERROR('Verifica que MinIO esté ejecutándose y las credenciales sean correctas')
                )
                return

            # Crear bucket principal si no existe
            try:
                if not minio_service.client.bucket_exists(minio_service.bucket_name):
                    minio_service.client.make_bucket(minio_service.bucket_name)
                    self.stdout.write(
                        self.style.SUCCESS(f'Bucket creado: {minio_service.bucket_name}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'Bucket ya existe: {minio_service.bucket_name}')
                    )

                # Verificar que el bucket sea accesible
                objects = list(minio_service.client.list_objects(minio_service.bucket_name, recursive=True))
                self.stdout.write(
                    self.style.SUCCESS(f'Bucket verificado - {len(objects)} objetos encontrados')
                )

                # Crear directorios virtuales de ejemplo
                self.stdout.write('Creando estructura de directorios virtuales...')

                # MinIO no tiene directorios reales, pero podemos crear algunos objetos de prueba
                test_directories = [
                    'user_1/.keep',
                    'user_2/.keep',
                    'temp/.keep'
                ]

                for test_dir in test_directories:
                    try:
                        # Solo crear si no existe
                        try:
                            minio_service.client.stat_object(minio_service.bucket_name, test_dir)
                            self.stdout.write(f'Ya existe: {test_dir}')
                        except:
                            # No existe, crearlo
                            from io import BytesIO
                            minio_service.client.put_object(
                                minio_service.bucket_name,
                                test_dir,
                                BytesIO(b''),
                                0
                            )
                            self.stdout.write(f'Creado: {test_dir}')
                    except Exception as e:
                        self.stdout.write(
                            self.style.WARNING(f'Error creando {test_dir}: {e}')
                        )

                self.stdout.write(
                    self.style.SUCCESS(
                        f'\nConfiguración de MinIO completada exitosamente'
                        f'\nBucket: {minio_service.bucket_name}'
                        f'\nEndpoint: {minio_service.client._base_url}'
                        f'\nServicio de encriptación: Habilitado'
                    )
                )

            except S3Error as e:
                self.stdout.write(
                    self.style.ERROR(f'Error S3 creando bucket: {e}')
                )
                return
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error inesperado: {e}')
                )
                return

        except ImportError as e:
            self.stdout.write(
                self.style.ERROR(f'Error importando MinIOService: {e}')
            )
            self.stdout.write(
                self.style.ERROR('Verifica que minio_service.py esté en la ubicación correcta')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error inesperado: {e}')
            )
            import traceback
            self.stdout.write(traceback.format_exc())
