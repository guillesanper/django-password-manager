# N17: altas a la espera de confirmar el email. Tabla nueva y vacía: `migrate` no toca
# ninguna fila existente, y las cuentas ya creadas siguen como están.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("myapp", "0028_revokedsession"),
    ]

    operations = [
        migrations.CreateModel(
            name="PendingRegistration",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("email", models.EmailField(db_index=True, max_length=254)),
                ("first_name", models.CharField(max_length=30)),
                ("last_name", models.CharField(max_length=30)),
                ("password_hash", models.CharField(max_length=128)),
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("failed_attempts", models.PositiveSmallIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
            ],
        ),
    ]
