# Generated by Django 5.1 on 2024-08-08 15:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("myapp", "0002_user_firstname"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="firstName",
            field=models.CharField(default="user", max_length=100),
        ),
    ]
