"""Intentos fallidos por origen, para el límite por IP del acceso y de la recuperación (A10).

Solo PostgreSQL. app_rw tiene SELECT e INSERT; nunca UPDATE ni DELETE, y los disparadores de
inmutabilidad (mediciones_rechazar_modificacion, de la migración mediciones 0004) rechazan UPDATE,
DELETE y TRUNCATE también para el dueño. El sello lo fija la base con now(). No hay RLS: las filas
no pertenecen a una persona (el origen es un HMAC de la IP). Ninguna función es SECURITY DEFINER y
todas fijan search_path.
"""

import uuid

import django.db.models.functions.datetime
from django.db import migrations, models

TABLA = "interfaz_intentofallido"

FUNCION_SELLO = """
CREATE FUNCTION interfaz_intentofallido_sello() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.sello := now();
    RETURN NEW;
END;
$$
"""

DISPARADORES = [
    FUNCION_SELLO,
    f"CREATE TRIGGER {TABLA}_sello BEFORE INSERT ON {TABLA}"
    " FOR EACH ROW EXECUTE FUNCTION interfaz_intentofallido_sello()",
    f"CREATE TRIGGER {TABLA}_inmutable BEFORE UPDATE OR DELETE ON {TABLA}"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_rechazar_modificacion()",
    f"CREATE TRIGGER {TABLA}_sin_truncate BEFORE TRUNCATE ON {TABLA}"
    " FOR EACH STATEMENT EXECUTE FUNCTION mediciones_rechazar_modificacion()",
]
QUITAR_DISPARADORES = [
    f"DROP TRIGGER {TABLA}_sin_truncate ON {TABLA}",
    f"DROP TRIGGER {TABLA}_inmutable ON {TABLA}",
    f"DROP TRIGGER {TABLA}_sello ON {TABLA}",
    "DROP FUNCTION interfaz_intentofallido_sello()",
]

PERMISOS = f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        GRANT SELECT, INSERT ON {TABLA} TO app_rw;
    END IF;
END
$$
"""
QUITAR_PERMISOS = f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        REVOKE ALL ON {TABLA} FROM app_rw;
    END IF;
END
$$
"""


class Migration(migrations.Migration):

    initial = True
    dependencies = [
        ('mediciones', '0004_reglas_inmutabilidad_rls'),
    ]

    operations = [
        migrations.CreateModel(
            name='IntentoFallido',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('ambito', models.CharField(choices=[('acceso', 'Acceso'), ('recuperacion', 'Recuperación')], max_length=15)),
                ('origen', models.CharField(max_length=64)),
                ('sello', models.DateTimeField(db_default=django.db.models.functions.datetime.Now())),
            ],
            options={
                'indexes': [models.Index(fields=['ambito', 'origen', 'sello'], name='intentofallido_origen_sello')],
                'constraints': [
                    models.CheckConstraint(condition=models.Q(('ambito__in', ['acceso', 'recuperacion'])), name='intentofallido_ambito_valido'),
                    models.CheckConstraint(condition=models.Q(('origen__regex', '^[0-9a-f]{64}$')), name='intentofallido_origen_hex'),
                ],
            },
        ),
        migrations.RunSQL(sql=DISPARADORES, reverse_sql=QUITAR_DISPARADORES),
        migrations.RunSQL(sql=[PERMISOS], reverse_sql=[QUITAR_PERMISOS]),
    ]
