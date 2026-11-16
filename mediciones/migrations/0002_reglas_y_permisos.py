"""Inmutabilidad de los períodos (sin borrado; cierre único e irreversible) y permisos de app_rw.

Solo PostgreSQL. Se ejecuta con el rol migrador, que queda como dueño de los objetos.
"""

from django.db import migrations

FUNCION_PERIODO = """
CREATE FUNCTION mediciones_periodo_inmutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Los períodos no se pueden borrar.';
    END IF;
    IF OLD.estado = 'cerrado' THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'El período está cerrado: el cierre es irreversible y no admite cambios.';
    END IF;
    IF NEW.estado <> 'cerrado'
       OR NEW.id <> OLD.id
       OR NEW.inicio <> OLD.inicio
       OR NEW.fin <> OLD.fin THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Solo se permite cerrar un período abierto, sin cambiar sus fechas.';
    END IF;
    RETURN NEW;
END;
$$
"""

TRIGGER_PERIODO = """
CREATE TRIGGER mediciones_periodo_inmutable
BEFORE UPDATE OR DELETE ON mediciones_periodo
FOR EACH ROW
EXECUTE FUNCTION mediciones_periodo_inmutable()
"""

PERMISOS_APP_RW = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        GRANT SELECT, INSERT ON mediciones_periodo TO app_rw;
        GRANT UPDATE (estado, cerrado_en, cerrado_por_id) ON mediciones_periodo TO app_rw;
    END IF;
END
$$
"""

REVOCAR_APP_RW = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        REVOKE ALL ON mediciones_periodo FROM app_rw;
    END IF;
END
$$
"""


class Migration(migrations.Migration):
    dependencies = [
        ("mediciones", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[FUNCION_PERIODO, TRIGGER_PERIODO],
            reverse_sql=[
                "DROP TRIGGER mediciones_periodo_inmutable ON mediciones_periodo",
                "DROP FUNCTION mediciones_periodo_inmutable()",
            ],
        ),
        migrations.RunSQL(sql=[PERMISOS_APP_RW], reverse_sql=[REVOCAR_APP_RW]),
    ]
