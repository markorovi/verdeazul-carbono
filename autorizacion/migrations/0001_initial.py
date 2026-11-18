"""Registro de intentos de lectura (T5 del diseño de autorización).

Solo PostgreSQL. app_rw tiene SELECT e INSERT; nunca UPDATE ni DELETE, y los disparadores de
inmutabilidad (mediciones_rechazar_modificacion, de la migración mediciones 0004) rechazan
UPDATE, DELETE y TRUNCATE también para el dueño. El sello lo fija la base con now(). La RLS
(ENABLE y FORCE) limita SELECT e INSERT a las filas del propio actor (app_usuario_actual), así que
los contadores de H2 de un usuario solo se calculan con sus propias lecturas. Ninguna función es
SECURITY DEFINER y todas fijan search_path.
"""

import uuid

import django.db.models.deletion
import django.db.models.functions.datetime
from django.conf import settings
from django.db import migrations, models

TABLA = "autorizacion_registroacceso"

FUNCION_SELLO = """
CREATE FUNCTION autorizacion_registroacceso_sello() RETURNS trigger
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
    " FOR EACH ROW EXECUTE FUNCTION autorizacion_registroacceso_sello()",
    f"CREATE TRIGGER {TABLA}_inmutable BEFORE UPDATE OR DELETE ON {TABLA}"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_rechazar_modificacion()",
    f"CREATE TRIGGER {TABLA}_sin_truncate BEFORE TRUNCATE ON {TABLA}"
    " FOR EACH STATEMENT EXECUTE FUNCTION mediciones_rechazar_modificacion()",
]
QUITAR_DISPARADORES = [
    f"DROP TRIGGER {TABLA}_sin_truncate ON {TABLA}",
    f"DROP TRIGGER {TABLA}_inmutable ON {TABLA}",
    f"DROP TRIGGER {TABLA}_sello ON {TABLA}",
    "DROP FUNCTION autorizacion_registroacceso_sello()",
]

RLS = [f"ALTER TABLE {TABLA} ENABLE ROW LEVEL SECURITY", f"ALTER TABLE {TABLA} FORCE ROW LEVEL SECURITY"]
QUITAR_RLS = [f"ALTER TABLE {TABLA} NO FORCE ROW LEVEL SECURITY", f"ALTER TABLE {TABLA} DISABLE ROW LEVEL SECURITY"]

POLITICAS_Y_PERMISOS = f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        CREATE POLICY registroacceso_lectura ON {TABLA} AS PERMISSIVE FOR SELECT TO app_rw
            USING (usuario_id = app_usuario_actual());
        CREATE POLICY registroacceso_registro ON {TABLA} AS PERMISSIVE FOR INSERT TO app_rw
            WITH CHECK (usuario_id = app_usuario_actual());
        GRANT SELECT, INSERT ON {TABLA} TO app_rw;
    END IF;
END
$$
"""
QUITAR_POLITICAS_Y_PERMISOS = f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        DROP POLICY IF EXISTS registroacceso_lectura ON {TABLA};
        DROP POLICY IF EXISTS registroacceso_registro ON {TABLA};
        REVOKE ALL ON {TABLA} FROM app_rw;
    END IF;
END
$$
"""


class Migration(migrations.Migration):

    initial = True
    dependencies = [
        ('catalogo', '0002_geometria_reglas_y_permisos'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='RegistroAcceso',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('operacion', models.CharField(max_length=10)),
                ('ajena', models.BooleanField()),
                ('resultado', models.CharField(choices=[('concedido', 'Concedido'), ('denegado', 'Denegado')], max_length=10)),
                ('motivo', models.CharField(blank=True, max_length=20, null=True)),
                ('sello', models.DateTimeField(db_default=django.db.models.functions.datetime.Now())),
                ('parcela', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='catalogo.parcela')),
                ('usuario', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'indexes': [models.Index(fields=['usuario', 'sello'], name='registroacceso_usuario_sello')],
                'constraints': [models.CheckConstraint(condition=models.Q(('resultado__in', ['concedido', 'denegado'])), name='registroacceso_resultado_valido')],
            },
        ),
        migrations.RunSQL(sql=DISPARADORES, reverse_sql=QUITAR_DISPARADORES),
        migrations.RunSQL(sql=RLS, reverse_sql=QUITAR_RLS),
        migrations.RunSQL(sql=[POLITICAS_Y_PERMISOS], reverse_sql=[QUITAR_POLITICAS_Y_PERMISOS]),
    ]