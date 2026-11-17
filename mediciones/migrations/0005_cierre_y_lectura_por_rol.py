"""Apertura y cierre de períodos solo por R7, y puerta de rol en las políticas de lectura.

Solo PostgreSQL. Ninguna función es SECURITY DEFINER y todas fijan search_path.
"""

from django.db import migrations

FUNCION_APERTURA = """
CREATE FUNCTION mediciones_periodo_apertura() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    IF NOT app_tiene_rol('R7') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Período rechazado: solo un actor con el rol R7 vigente abre períodos.';
    END IF;
    -- Un período no puede nacer cerrado: el cierre solo ocurre por UPDATE, con fecha y autor de la base.
    IF NEW.estado <> 'abierto' OR NEW.cerrado_en IS NOT NULL OR NEW.cerrado_por_id IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Período rechazado: un período nuevo empieza abierto, sin fecha ni autor de cierre.';
    END IF;
    RETURN NEW;
END;
$$
"""

TRIGGER_APERTURA = (
    "CREATE TRIGGER mediciones_periodo_apertura BEFORE INSERT ON mediciones_periodo"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_periodo_apertura()"
)

_INMUTABLE_COMUN = """
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
"""

_CIERRE_POR_R7 = """
    IF NOT app_tiene_rol('R7') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Cierre rechazado: solo un actor con el rol R7 vigente cierra períodos.';
    END IF;
    -- La fecha y el autor del cierre los fija la base; lo que envíe el cliente se ignora.
    NEW.cerrado_en := now();
    NEW.cerrado_por_id := app_usuario_actual();
"""


def _funcion_inmutable(cuerpo_extra: str) -> str:
    return f"""
CREATE OR REPLACE FUNCTION mediciones_periodo_inmutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
{_INMUTABLE_COMUN}{cuerpo_extra}
    RETURN NEW;
END;
$$
"""


FUNCION_INMUTABLE_CON_CIERRE = _funcion_inmutable(_CIERRE_POR_R7)
FUNCION_INMUTABLE_ORIGINAL = _funcion_inmutable("")

FUNCION_LECTURA = """
CREATE FUNCTION app_tiene_rol_de_lectura() RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
    SELECT app_tiene_rol('R1') OR app_tiene_rol('R2') OR app_tiene_rol('R5')
        OR app_tiene_rol('R6') OR app_tiene_rol('R7')
$$
"""

# (tabla, política, predicado de lectura vigente desde la migración 0004).
POLITICAS_LECTURA = [
    ("mediciones_medicion", "medicion_lectura", "app_puede_ver_parcela(parcela_id)"),
    ("mediciones_medicionversion", "version_lectura", "app_puede_ver_medicion(medicion_id)"),
    ("mediciones_aprobacion", "aprobacion_lectura", "app_puede_ver_medicion(medicion_id)"),
    ("mediciones_enmienda", "enmienda_lectura", "app_puede_ver_medicion(medicion_id)"),
    ("mediciones_certificado", "certificado_lectura", "app_puede_ver_parcela(parcela_id)"),
]


def _alterar_politicas(con_puerta: bool) -> str:
    """Las políticas solo existen si app_rw existía al migrar; si faltan, no hay nada que alterar."""
    sentencias = []
    for tabla, politica, predicado in POLITICAS_LECTURA:
        uso = f"app_tiene_rol_de_lectura() AND {predicado}" if con_puerta else predicado
        sentencias.append(
            f"""
    IF EXISTS (SELECT 1 FROM pg_policies
                WHERE schemaname = 'public' AND tablename = '{tabla}' AND policyname = '{politica}') THEN
        ALTER POLICY {politica} ON {tabla} USING ({uso});
    END IF;"""
        )
    return "DO $$\nBEGIN" + "".join(sentencias) + "\nEND\n$$"


class Migration(migrations.Migration):
    dependencies = [
        ("mediciones", "0004_reglas_inmutabilidad_rls"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[FUNCION_APERTURA, TRIGGER_APERTURA],
            reverse_sql=[
                "DROP TRIGGER mediciones_periodo_apertura ON mediciones_periodo",
                "DROP FUNCTION mediciones_periodo_apertura()",
            ],
        ),
        migrations.RunSQL(sql=[FUNCION_INMUTABLE_CON_CIERRE], reverse_sql=[FUNCION_INMUTABLE_ORIGINAL]),
        migrations.RunSQL(sql=[FUNCION_LECTURA], reverse_sql=["DROP FUNCTION app_tiene_rol_de_lectura()"]),
        migrations.RunSQL(sql=[_alterar_politicas(True)], reverse_sql=[_alterar_politicas(False)]),
    ]
