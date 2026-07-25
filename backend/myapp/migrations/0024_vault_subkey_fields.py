# Fase 2 (zero-knowledge) — migración ADITIVA (paso 24, bóvedas privadas / A9).
# Añade a Vault el material de subclave zero-knowledge por bóveda privada. NO altera ni elimina
# los campos legados (vault_password_hash, vault_salt), que se conservan hasta la purga del
# paso 26/27. Escrita a mano a propósito: `makemigrations` arrastraría la reevaluación de la sal
# global (C2) sobre masterkey.salt/passwordentry.salt, que muere en el paso de purga.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0023_passwordentry_client_id_encryptedfile_client_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='vault',
            name='sub_kdf_salt',
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name='vault',
            name='sub_kdf_params',
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name='vault',
            name='sub_auth_key_hash',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='vault',
            name='wrapped_vault_subkey',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='vault',
            name='vault_crypto_version',
            field=models.PositiveSmallIntegerField(default=1),
        ),
    ]
