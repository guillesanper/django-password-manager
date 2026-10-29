# N12: tamaño del blob guardado en la BD al subir, para que `api_files` no haga un stat_object
# en MinIO por cada fichero. Aditiva y nula: `migrate` no necesita MinIO. Los ficheros ya
# subidos se rellenan aparte con `manage.py backfill_file_sizes`, con MinIO en pie.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0026_drop_encrypted_file_field'),
    ]

    operations = [
        migrations.AddField(
            model_name='encryptedfile',
            name='size',
            field=models.BigIntegerField(blank=True, null=True),
        ),
    ]
