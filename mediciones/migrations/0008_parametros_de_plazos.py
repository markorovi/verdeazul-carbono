"""Parámetros de política de plazos que faltaban: verificación, ventana del auditor y emergencias.

Solo PostgreSQL. Idempotente: ON CONFLICT DO NOTHING no toca un parámetro que ya exista (la tabla es
inmutable y el disparador rechaza UPDATE y DELETE). Mismo formato que los parámetros de la 0004:
clave, valor numérico y una descripción que indica la unidad.

La reversa no borra filas: el disparador de inmutabilidad lo impide y un parámetro sembrado puede
haber existido antes de esta migración.
"""

from django.db import migrations

PARAMETROS = [
    ("tver_dias_habiles", "15", "Plazo en días hábiles desde el cierre del período para verificar una medición (Cd19)"),
    ("waud_dias_anuales", "30", "Días por año que puede durar en total la ventana de un auditor externo"),
    ("temg_horas", "4", "Vigencia máxima de un acceso de emergencia, en horas"),
    ("trev_emg_horas", "24", "Plazo para revisar un acceso de emergencia después de usarlo, en horas"),
]


class Migration(migrations.Migration):
    dependencies = [
        ("mediciones", "0007_verificador_asignado"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[
                (
                    "INSERT INTO mediciones_politicaparametro (clave, valor, descripcion) VALUES (%s, %s, %s)"
                    " ON CONFLICT (clave) DO NOTHING",
                    [clave, valor, descripcion],
                )
                for clave, valor, descripcion in PARAMETROS
            ],
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
