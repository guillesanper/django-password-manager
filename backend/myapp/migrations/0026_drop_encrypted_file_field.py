# Fase 2 (zero-knowledge) — paso 28: purga del último residuo v1 de EncryptedFile.
# `encrypted_file` (FileField, upload_to='encrypted_files/') era el almacenamiento local legado.
# En v2 el objeto vive en MinIO (`file_path`) y su contenido se cifra en el cliente; ninguna vista
# v2 escribe ni lee este campo (verificado por grep en el paso 28). Se retira ahora, junto con la
# capa Fernet at-rest de MinIO (sustituida por SSE-S3). Destructiva y a mano, como 0022–0025;
# ruptura de datos aceptada (BD/volúmenes vacíos).

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0025_purge_legacy_crypto'),
    ]

    operations = [
        migrations.RemoveField(model_name='encryptedfile', name='encrypted_file'),
    ]
