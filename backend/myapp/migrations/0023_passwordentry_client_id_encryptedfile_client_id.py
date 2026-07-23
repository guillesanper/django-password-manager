# Fase 2 (zero-knowledge) — migración ADITIVA: identidad estable por cliente (decisión 1b).
# client_id (UUID) es parte de la AAD de cada entrada/fichero. `unique=True` impide el swap de
# ciphertext+client_id entre filas por un atacante con escritura en BD. NULL para los legacy (v1).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0022_usercrypto_aead_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='passwordentry',
            name='client_id',
            field=models.UUIDField(blank=True, null=True, unique=True),
        ),
        migrations.AddField(
            model_name='encryptedfile',
            name='client_id',
            field=models.UUIDField(blank=True, null=True, unique=True),
        ),
    ]
