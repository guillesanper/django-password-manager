# Fase 2 (zero-knowledge) — paso 26: PURGA del esquema legado (destructiva).
# A diferencia de 0022–0024 (aditivas), esta migración ELIMINA el modelo y los campos v1 que ya
# no escribe ni lee ningún flujo v2. Se acepta la ruptura de datos: BD y volúmenes vacíos.
#
# Purga:
#   - Modelo MasterKey entero (C1: `hashed_key` era la clave de cifrado; C2: `salt` global en git).
#   - PasswordEntry: columnas del esquema v1 (sitio/usuario en claro + cripto de servidor). El
#     sitio, el usuario y la contraseña viajan ahora cifrados dentro de `ciphertext`.
#   - EncryptedFile: metadatos y cripto v1. El título, los metadatos y la clave de fichero van
#     dentro de `ciphertext`. `encrypted_file` (FileField) se conserva hasta el paso 28.
#   - Vault: contraseña de bóveda privada legada (PBKDF2 verificado en servidor); las privadas v2
#     usan `wrapped_vault_subkey` + `sub_auth_key_hash` (paso 24).
#
# Escrita a mano a propósito (como 0022–0024): `makemigrations` no corre fiable fuera de Docker y
# arrastraría la reevaluación de la sal global (C2) congelada en 0007–0021. Aquí, además, borrar
# `passwordentry.salt`/`masterkey.salt` mata esa sal global de raíz.

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0024_vault_subkey_fields'),
    ]

    operations = [
        # --- PasswordEntry: columnas v1 en claro + cripto de servidor ---
        migrations.RemoveField(model_name='passwordentry', name='website'),
        migrations.RemoveField(model_name='passwordentry', name='username'),
        migrations.RemoveField(model_name='passwordentry', name='encrypted_password'),
        migrations.RemoveField(model_name='passwordentry', name='encryption_algorithm'),
        migrations.RemoveField(model_name='passwordentry', name='salt'),
        migrations.RemoveField(model_name='passwordentry', name='iv_or_nonce'),
        migrations.RemoveField(model_name='passwordentry', name='encrypted_key'),

        # --- EncryptedFile: metadatos en claro + cripto v1 ---
        migrations.RemoveField(model_name='encryptedfile', name='title'),
        migrations.RemoveField(model_name='encryptedfile', name='salt'),
        migrations.RemoveField(model_name='encryptedfile', name='iv_or_nonce'),
        migrations.RemoveField(model_name='encryptedfile', name='algorithm'),
        migrations.RemoveField(model_name='encryptedfile', name='encrypted_key'),

        # --- Vault: contraseña de bóveda privada legada (PBKDF2) ---
        migrations.RemoveField(model_name='vault', name='vault_password_hash'),
        migrations.RemoveField(model_name='vault', name='vault_salt'),

        # --- MasterKey: fallo raíz C1/C2, purgado entero ---
        migrations.DeleteModel(name='MasterKey'),
    ]
