"""Documento firmado Ed25519 en los certificados y validación del payload contra la base.

Solo PostgreSQL. La base valida que el payload coincida con sus datos, pero no verifica la firma
(eso ocurre en la aplicación y en scripts/verify_cert.py). Ninguna función es SECURITY DEFINER y
todas fijan search_path. app_rw inserta las columnas nuevas pero no puede actualizarlas: no se
agregan a sus GRANT UPDATE por columna.
"""

from django.db import migrations, models

ERROR = "integrity_constraint_violation"

# Con FORCE ROW LEVEL SECURITY el dueño no ve filas; para contarlas se quita FORCE dentro de la
# misma transacción de la migración y se restaura antes de seguir.
EXIGIR_TABLA_VACIA = f"""
DO $$
DECLARE
    v_cantidad bigint;
BEGIN
    ALTER TABLE mediciones_certificado NO FORCE ROW LEVEL SECURITY;
    SELECT count(*) INTO v_cantidad FROM mediciones_certificado;
    ALTER TABLE mediciones_certificado FORCE ROW LEVEL SECURITY;
    IF v_cantidad > 0 THEN
        RAISE EXCEPTION USING ERRCODE = '{ERROR}',
            MESSAGE = format('Migración detenida: hay %s certificados sin firma; esta migración exige la tabla vacía.', v_cantidad);
    END IF;
END
$$
"""

CAMPOS_PAYLOAD = [
    "certificado_id",
    "parcela_id",
    "periodo_id",
    "medicion_id",
    "medicion_numero",
    "co2e_toneladas",
    "huella_medicion",
    "aprobadores",
    "fecha_emision",
    "version_politica",
    "key_id",
]
ARREGLO_CAMPOS = "ARRAY[" + ", ".join(f"'{c}'" for c in CAMPOS_PAYLOAD) + "]"


def _rechazo(mensaje: str) -> str:
    return f"RAISE EXCEPTION USING ERRCODE = '{ERROR}', MESSAGE = 'Certificado rechazado: {mensaje}';"


def _si(condicion: str, mensaje: str) -> str:
    return f"""
    IF {condicion} THEN
        {_rechazo(mensaje)}
    END IF;"""


FUNCION_FIRMA = f"""
CREATE FUNCTION mediciones_certificado_firma() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
    p jsonb := NEW.payload;
    v_version mediciones_medicionversion%ROWTYPE;
    v_aprobadores jsonb;
    v_fecha timestamptz;
BEGIN
{_si("jsonb_typeof(p) IS DISTINCT FROM 'object'", "el payload no es un objeto JSON.")}
{_si(f"(SELECT count(*) FROM jsonb_object_keys(p)) <> {len(CAMPOS_PAYLOAD)} OR NOT (p ?& {ARREGLO_CAMPOS})",
     "el payload debe tener exactamente los 11 campos firmados.")}
{_si("NEW.alg IS DISTINCT FROM 'Ed25519'", "alg debe ser Ed25519.")}
{_si("NEW.clave_publica !~ '^[A-Za-z0-9+/]{43}=$'", "clave_publica no es base64 de 32 bytes.")}
{_si("NEW.firma !~ '^[A-Za-z0-9+/]{86}==$'", "firma no es base64 de 64 bytes.")}
{_si("NEW.key_id IS DISTINCT FROM left(encode(sha256(decode(NEW.clave_publica, 'base64')), 'hex'), 16)",
     "key_id no corresponde a la clave pública.")}
{_si("p->>'key_id' IS DISTINCT FROM NEW.key_id", "payload.key_id no coincide con key_id.")}
{_si("p->>'certificado_id' IS DISTINCT FROM NEW.id::text", "payload.certificado_id no coincide con el id del certificado.")}
{_si("p->>'parcela_id' IS DISTINCT FROM NEW.parcela_id::text", "payload.parcela_id no coincide con la parcela del certificado.")}
{_si("p->>'periodo_id' IS DISTINCT FROM NEW.periodo_id::text", "payload.periodo_id no coincide con el período del certificado.")}
{_si("p->>'medicion_id' IS DISTINCT FROM NEW.medicion_id::text", "payload.medicion_id no coincide con la medición del certificado.")}
    SELECT * INTO v_version FROM mediciones_medicionversion WHERE id = NEW.version_id;
{_si("NOT FOUND", "la versión certificada no existe o no es visible para el actor.")}
{_si("jsonb_typeof(p->'medicion_numero') IS DISTINCT FROM 'number' OR p->>'medicion_numero' IS DISTINCT FROM v_version.numero::text",
     "payload.medicion_numero no coincide con el número de la versión aprobada.")}
{_si("p->>'co2e_toneladas' IS DISTINCT FROM v_version.co2e_toneladas::text",
     "payload.co2e_toneladas no coincide con el valor de la versión (3 decimales).")}
{_si("p->>'huella_medicion' IS DISTINCT FROM v_version.huella", "payload.huella_medicion no coincide con la huella de la versión.")}
    SELECT coalesce(jsonb_agg(s ORDER BY s), '[]'::jsonb) INTO v_aprobadores
      FROM (SELECT DISTINCT left(encode(sha256(convert_to(a.aprobador_id::text, 'UTF8')), 'hex'), 16) AS s
              FROM mediciones_aprobacion a
             WHERE a.medicion_id = NEW.medicion_id AND a.ciclo = NEW.ciclo
               AND a.version_id = NEW.version_id AND a.huella_aprobada = v_version.huella) AS seudonimos;
{_si("p->'aprobadores' IS DISTINCT FROM v_aprobadores", "payload.aprobadores no coincide con quienes aprobaron la versión.")}
{_si("jsonb_typeof(p->'version_politica') IS DISTINCT FROM 'string' OR p->>'version_politica' = ''",
     "payload.version_politica falta o está vacía.")}
{_si("jsonb_typeof(p->'fecha_emision') IS DISTINCT FROM 'string' OR p->>'fecha_emision' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'",
     "payload.fecha_emision no está en UTC ISO 8601 con sufijo Z.")}
    BEGIN
        v_fecha := (p->>'fecha_emision')::timestamptz;
    EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
        {_rechazo("payload.fecha_emision no es una fecha válida.")}
    END;
{_si("abs(extract(epoch FROM (now() - v_fecha))) > 60", "payload.fecha_emision está a más de 60 segundos de la hora de la base.")}
    RETURN NEW;
END;
$$
"""

FUNCION_FIRMA_INMUTABLE = f"""
CREATE FUNCTION mediciones_certificado_firma_inmutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    IF NEW.payload IS DISTINCT FROM OLD.payload OR NEW.firma IS DISTINCT FROM OLD.firma
       OR NEW.clave_publica IS DISTINCT FROM OLD.clave_publica OR NEW.alg IS DISTINCT FROM OLD.alg
       OR NEW.key_id IS DISTINCT FROM OLD.key_id THEN
        RAISE EXCEPTION USING ERRCODE = '{ERROR}',
            MESSAGE = 'Certificado: el documento firmado (payload, firma, clave, alg y key_id) es inmutable.';
    END IF;
    RETURN NEW;
END;
$$
"""

DISPARADORES = [
    FUNCION_FIRMA,
    "CREATE TRIGGER mediciones_certificado_firma BEFORE INSERT ON mediciones_certificado"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_certificado_firma()",
    FUNCION_FIRMA_INMUTABLE,
    "CREATE TRIGGER mediciones_certificado_firma_inmutable BEFORE UPDATE ON mediciones_certificado"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_certificado_firma_inmutable()",
]
QUITAR_DISPARADORES = [
    "DROP TRIGGER mediciones_certificado_firma_inmutable ON mediciones_certificado",
    "DROP FUNCTION mediciones_certificado_firma_inmutable()",
    "DROP TRIGGER mediciones_certificado_firma ON mediciones_certificado",
    "DROP FUNCTION mediciones_certificado_firma()",
]


class Migration(migrations.Migration):
    dependencies = [
        ("mediciones", "0005_cierre_y_lectura_por_rol"),
    ]

    operations = [
        migrations.RunSQL(sql=[EXIGIR_TABLA_VACIA], reverse_sql=migrations.RunSQL.noop),
        migrations.AddField(
            model_name="certificado",
            name="payload",
            field=models.JSONField(default=dict),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="certificado",
            name="firma",
            field=models.TextField(default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="certificado",
            name="clave_publica",
            field=models.TextField(default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="certificado",
            name="alg",
            field=models.CharField(default="Ed25519", max_length=10),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="certificado",
            name="key_id",
            field=models.CharField(default="", max_length=16),
            preserve_default=False,
        ),
        migrations.AddConstraint(
            model_name="certificado",
            constraint=models.CheckConstraint(condition=models.Q(alg="Ed25519"), name="certificado_alg_ed25519"),
        ),
        migrations.RunSQL(sql=DISPARADORES, reverse_sql=QUITAR_DISPARADORES),
    ]
