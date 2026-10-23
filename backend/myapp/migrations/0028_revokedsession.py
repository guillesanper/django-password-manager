# N14: logins terminados desde la pantalla de sesiones, por su `sid`. Tabla nueva y vacía:
# `migrate` no toca ninguna fila existente.

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("myapp", "0027_encryptedfile_size"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="RevokedSession",
            fields=[
                (
                    "sid",
                    models.CharField(max_length=64, primary_key=True, serialize=False),
                ),
                ("revoked_at", models.DateTimeField(auto_now_add=True)),
                ("expires_at", models.DateTimeField(db_index=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="revoked_sessions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
