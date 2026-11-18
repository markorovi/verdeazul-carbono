"""Cuenta afectada y justificación de resolución en las alertas (Cd14 y Cd18).

Solo PostgreSQL. Columnas nullables: el aviso de anulación de certificados sigue igual. app_rw ya
inserta en la tabla; recibe UPDATE solo sobre justificacion_resolucion, que el disparador de
resolución existente deja cambiar una única vez, junto con resuelta_en y resuelta_por.

La restricción alerta_resolucion_independiente impide en la base que resuelva quien es parte de la
alerta. La justificación mínima la exige el servicio de resolución: la base sigue admitiendo
resoluciones sin justificación hechas antes de existir la columna.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def _bloque_app_rw(sentencia: str) -> str:
    """Solo corre si existe app_rw (sin él, nadie escribe: falla cerrado)."""
    return f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        {sentencia};
    END IF;
END
$$
"""


class Migration(migrations.Migration):
    dependencies = [
        ("catalogo", "0002_geometria_reglas_y_permisos"),
        ("mediciones", "0008_parametros_de_plazos"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="alerta",
            name="cuenta_afectada",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="alerta",
            name="justificacion_resolucion",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddConstraint(
            model_name="alerta",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    ("resuelta_por__isnull", True),
                    models.Q(
                        models.Q(("resuelta_por", models.F("usuario")), _negated=True),
                        models.Q(("resuelta_por", models.F("cuenta_afectada")), _negated=True),
                    ),
                    _connector="OR",
                ),
                name="alerta_resolucion_independiente",
            ),
        ),
        migrations.RunSQL(
            sql=[_bloque_app_rw("GRANT UPDATE (justificacion_resolucion) ON mediciones_alerta TO app_rw")],
            reverse_sql=[_bloque_app_rw("REVOKE UPDATE (justificacion_resolucion) ON mediciones_alerta FROM app_rw")],
        ),
    ]
