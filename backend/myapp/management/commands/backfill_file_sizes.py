from django.core.management.base import BaseCommand

from myapp.minio_service import enhanced_minio_service
from myapp.models import EncryptedFile


class Command(BaseCommand):
    """Rellena `EncryptedFile.size` de los ficheros subidos antes de N12.

    Desde N12 el tamaño se guarda al subir y `api_files` no pregunta a MinIO; los anteriores
    salen sin tamaño hasta ejecutar esto una vez con MinIO en pie. Es idempotente: sólo toca
    los que aún no lo tienen, así que se puede repetir si MinIO falló a medias.
    """

    help = 'Rellena el tamaño de los ficheros subidos antes de guardarlo en la BD (N12)'

    def handle(self, *args, **options):
        pendientes = EncryptedFile.objects.filter(size__isnull=True).exclude(file_path__isnull=True)
        rellenados = fallidos = 0
        for file_entry in pendientes.iterator():
            info = enhanced_minio_service.get_file_info(file_entry.file_path)
            if not info['success']:
                fallidos += 1
                self.stdout.write(self.style.WARNING(
                    f"Sin tamaño: id={file_entry.id} ({info['error']})"
                ))
                continue
            # update() y no save(): save() renovaría `updated_at`, que el cliente muestra como
            # fecha del fichero.
            EncryptedFile.objects.filter(pk=file_entry.pk).update(size=info['info']['size'])
            rellenados += 1

        self.stdout.write(self.style.SUCCESS(
            f"Tamaños rellenados: {rellenados}; sin rellenar: {fallidos}"
        ))
