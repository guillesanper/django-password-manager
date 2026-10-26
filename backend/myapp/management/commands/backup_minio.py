"""Copia del bucket de ficheros a un directorio local, y vuelta (N18, AU-17).

    python manage.py backup_minio /backups/minio            # baja lo que falte o haya cambiado
    python manage.py backup_minio /backups/minio --restore  # sube lo que falte en el bucket

La copia va por la API S3, así que MinIO entrega los objetos ya sin su cifrado SSE-S3: no hace
falta MINIO_KMS_SECRET_KEY para restaurarla. El contenido sigue siendo el blob cifrado en el
navegador (zero-knowledge): el servidor no lo puede leer, ni antes ni ahora.

No borra nada de la copia aunque se haya borrado del bucket: una réplica de los borrados no
sirve para recuperar un borrado por error. La contrapartida es que la copia sólo crece.
"""

import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from minio.error import S3Error
from minio.sse import SseS3

from myapp.minio_service import enhanced_minio_service

CHUNK = 64 * 1024


def _local_path(root, object_name):
    """Ruta local de un objeto. Una clave con `..` o absoluta no puede escribir fuera de `root`."""
    path = (root / object_name).resolve()
    if path != root and root not in path.parents:
        raise CommandError(f"La clave {object_name!r} quedaría fuera del directorio de la copia")
    return path


class Command(BaseCommand):
    help = 'Copia el bucket de ficheros a un directorio local (o lo restaura con --restore)'

    def add_arguments(self, parser):
        parser.add_argument('directorio', help='Directorio de la copia')
        parser.add_argument('--restore', action='store_true',
                            help='Sube al bucket los ficheros de la copia que falten en él')

    def handle(self, *args, **options):
        root = Path(options['directorio']).resolve()
        client = enhanced_minio_service.client
        bucket = enhanced_minio_service.bucket_name
        if options['restore']:
            self._restore(client, bucket, root)
        else:
            self._backup(client, bucket, root)

    def _backup(self, client, bucket, root):
        root.mkdir(parents=True, exist_ok=True)
        downloaded = skipped = 0
        for obj in client.list_objects(bucket, recursive=True):
            path = _local_path(root, obj.object_name)
            if path.is_file() and path.stat().st_size == obj.size:
                skipped += 1
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            # A un temporal y renombrado al final: un corte a mitad no deja un fichero con el
            # tamaño equivocado que la siguiente pasada daría por bueno... o por malo, sin saberlo.
            part = path.with_name(path.name + '.part')
            response = client.get_object(bucket, obj.object_name)
            try:
                with open(part, 'wb') as fh:
                    fh.writelines(response.stream(CHUNK))
            finally:
                response.close()
                response.release_conn()
            os.replace(part, path)
            downloaded += 1
        self.stdout.write(f"backup_minio: {downloaded} bajados, {skipped} ya estaban")

    def _restore(self, client, bucket, root):
        if not root.is_dir():
            raise CommandError(f"No existe el directorio de la copia: {root}")
        uploaded = present = 0
        for path in sorted(p for p in root.rglob('*') if p.is_file()):
            if path.name.endswith('.part'):
                continue
            object_name = path.relative_to(root).as_posix()
            try:
                client.stat_object(bucket, object_name)
                present += 1
                continue
            except S3Error as exc:
                if exc.code not in ('NoSuchKey', 'NoSuchObject'):
                    raise
            with open(path, 'rb') as fh:
                # Igual que la subida de la app: cifrado at-rest con el KMS de MinIO.
                client.put_object(bucket, object_name, fh, path.stat().st_size, sse=SseS3())
            uploaded += 1
        self.stdout.write(f"backup_minio --restore: {uploaded} subidos, {present} ya estaban")
