# Fase 2 (zero-knowledge) — migración ADITIVA: no altera ni elimina campos existentes.
# Añade UserCrypto y los campos AEAD (crypto_version, ciphertext) a PasswordEntry y
# EncryptedFile. Los modelos legados (MasterKey, encrypted_password, salt, ...) se conservan
# intactos hasta la migración/purga de datos del paso 26.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0021_alter_activitylog_activity_type_alter_masterkey_salt_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserCrypto',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kdf_salt', models.CharField(max_length=64)),
                ('kdf_params', models.JSONField(default=dict)),
                ('auth_key_hash', models.CharField(max_length=255)),
                ('wrapped_vault_key', models.TextField()),
                ('crypto_version', models.PositiveSmallIntegerField(default=2)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='crypto', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='passwordentry',
            name='crypto_version',
            field=models.PositiveSmallIntegerField(default=1),
        ),
        migrations.AddField(
            model_name='passwordentry',
            name='ciphertext',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='encryptedfile',
            name='crypto_version',
            field=models.PositiveSmallIntegerField(default=1),
        ),
        migrations.AddField(
            model_name='encryptedfile',
            name='ciphertext',
            field=models.TextField(blank=True, null=True),
        ),
    ]
