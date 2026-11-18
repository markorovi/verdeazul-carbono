"""Verificador asignado a una medición, para reasignar la verificación (Cd19).

Solo PostgreSQL. Columna nullable; app_rw recibe UPDATE solo sobre ella. La política de UPDATE de la
medición deja escribir a R1 (sus mediciones), R2 y R7, y la RLS no distingue columnas: un disparador
limita el cambio de esta columna a un actor R7, con la medición presentada, el período cerrado y un
destino con R2 vigente. Las condiciones Cd8 y Cd19 del destino las aplica el servicio. Ninguna
función es SECURITY DEFINER y todas fijan search_path.
"""

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

ERROR = "integrity_constraint_violation"


def _error(mensaje: str) -> str:
    return f"RAISE EXCEPTION USING ERRCODE = '{ERROR}', MESSAGE = '{mensaje}';"


FUNCION_VERIFICADOR = f"""
CREATE FUNCTION mediciones_medicion_verificador() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
    v_periodo text;
BEGIN
    IF NOT app_tiene_rol('R7') THEN
        {_error("Reasignación rechazada: solo un actor con el rol R7 vigente asigna el verificador.")}
    END IF;
    IF OLD.estado <> 'presentada' OR NEW.estado <> 'presentada' THEN
        {_error("Reasignación rechazada (Cd19): la medición debe estar presentada.")}
    END IF;
    SELECT estado INTO v_periodo FROM mediciones_periodo WHERE id = NEW.periodo_id;
    IF v_periodo IS DISTINCT FROM 'cerrado' THEN
        {_error("Reasignación rechazada (Cd19): el período debe estar cerrado.")}
    END IF;
    IF NEW.verificador_asignado_id IS NULL OR NOT EXISTS (
        SELECT 1 FROM usuarios_rolusuario
         WHERE usuario_id = NEW.verificador_asignado_id AND rol_id = 'R2' AND hasta IS NULL) THEN
        {_error("Reasignación rechazada (Cd19): el destino debe tener el rol R2 vigente.")}
    END IF;
    RETURN NEW;
END;
$$
"""

TRIGGER_VERIFICADOR = (
    "CREATE TRIGGER mediciones_medicion_verificador BEFORE UPDATE ON mediciones_medicion FOR EACH ROW"
    " WHEN (OLD.verificador_asignado_id IS DISTINCT FROM NEW.verificador_asignado_id)"
    " EXECUTE FUNCTION mediciones_medicion_verificador()"
)


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
        ("mediciones", "0006_firma_certificados"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="medicion",
            name="verificador_asignado",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="+",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.RunSQL(
            sql=[FUNCION_VERIFICADOR, TRIGGER_VERIFICADOR],
            reverse_sql=[
                "DROP TRIGGER mediciones_medicion_verificador ON mediciones_medicion",
                "DROP FUNCTION mediciones_medicion_verificador()",
            ],
        ),
        migrations.RunSQL(
            sql=[_bloque_app_rw("GRANT UPDATE (verificador_asignado_id) ON mediciones_medicion TO app_rw")],
            reverse_sql=[_bloque_app_rw("REVOKE UPDATE (verificador_asignado_id) ON mediciones_medicion FROM app_rw")],
        ),
    ]
