"""Quién dio de alta cada cuenta, para la prioridad de los avisos de Cd14.

Columna nullable. app_rw ya tiene INSERT de tabla sobre usuarios_usuario y UPDATE solo por las
columnas concedidas en 0002 y 0003: no se le concede UPDATE sobre esta, así que solo se escribe al
insertar la cuenta.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("usuarios", "0003_autenticacion_totp"),
    ]

    operations = [
        migrations.AddField(
            model_name="usuario",
            name="creado_por",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
