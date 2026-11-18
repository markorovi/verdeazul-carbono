"""Geometría de parcelas (PostGIS), reglas de traslape y de asignación, y permisos de app_rw.

Solo PostgreSQL con PostGIS. Se ejecuta con el rol migrador, que queda como dueño de los objetos.
"""

from django.db import migrations

COLUMNA_GEOMETRIA = [
    "ALTER TABLE catalogo_parcela ADD COLUMN geom geometry(Polygon, 5367) NOT NULL",
    "ALTER TABLE catalogo_parcela ADD CONSTRAINT parcela_geom_valida CHECK (ST_IsValid(geom))",
    "ALTER TABLE catalogo_parcela ADD CONSTRAINT parcela_geom_srid CHECK (ST_SRID(geom) = 5367)",
    "CREATE INDEX catalogo_parcela_geom_gist ON catalogo_parcela USING gist (geom)",
]

QUITAR_COLUMNA_GEOMETRIA = [
    "DROP INDEX catalogo_parcela_geom_gist",
    "ALTER TABLE catalogo_parcela DROP CONSTRAINT parcela_geom_srid",
    "ALTER TABLE catalogo_parcela DROP CONSTRAINT parcela_geom_valida",
    "ALTER TABLE catalogo_parcela DROP COLUMN geom",
]

# Las geometrías inválidas o nulas se dejan pasar aquí para que las rechacen las restricciones
# CHECK y NOT NULL con su propio error. Una parcela dada de baja no ocupa espacio.
FUNCION_SIN_TRASLAPE = """
CREATE FUNCTION catalogo_parcela_sin_traslape() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
    parcela_en_conflicto uuid;
BEGIN
    IF NEW.dada_de_baja_en IS NOT NULL OR NEW.geom IS NULL OR NOT ST_IsValid(NEW.geom) THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('catalogo_parcela_geom'));
    SELECT p.id INTO parcela_en_conflicto
      FROM catalogo_parcela p
     WHERE p.id <> NEW.id
       AND p.dada_de_baja_en IS NULL
       AND p.geom && NEW.geom
       AND ST_Relate(NEW.geom, p.geom, 'T********')
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = format(
                'Traslape de parcelas: el polígono se superpone con la parcela %s'
                ' (solo se permite compartir bordes).',
                parcela_en_conflicto);
    END IF;
    RETURN NEW;
END;
$$
"""

TRIGGER_SIN_TRASLAPE = """
CREATE TRIGGER catalogo_parcela_sin_traslape
BEFORE INSERT OR UPDATE OF geom, dada_de_baja_en ON catalogo_parcela
FOR EACH ROW
EXECUTE FUNCTION catalogo_parcela_sin_traslape()
"""

FUNCION_TECNICO_R1 = """
CREATE FUNCTION catalogo_asignacion_requiere_r1() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM usuarios_rolusuario
         WHERE usuario_id = NEW.tecnico_id
           AND rol_id = 'R1'
           AND hasta IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = format(
                'Asignación rechazada: el usuario %s no tiene vigente el rol R1 (Técnico de Campo).',
                NEW.tecnico_id);
    END IF;
    RETURN NEW;
END;
$$
"""

TRIGGER_TECNICO_R1 = """
CREATE TRIGGER catalogo_asignacion_requiere_r1
BEFORE INSERT ON catalogo_asignacion
FOR EACH ROW
EXECUTE FUNCTION catalogo_asignacion_requiere_r1()
"""

PERMISOS_APP_RW = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        GRANT SELECT, INSERT ON catalogo_finca TO app_rw;
        GRANT UPDATE (nombre, dada_de_baja_en) ON catalogo_finca TO app_rw;
        GRANT SELECT, INSERT ON catalogo_parcela TO app_rw;
        GRANT UPDATE (codigo, geom, dada_de_baja_en) ON catalogo_parcela TO app_rw;
        GRANT SELECT, INSERT ON catalogo_propiedad TO app_rw;
        GRANT UPDATE (hasta) ON catalogo_propiedad TO app_rw;
        GRANT SELECT, INSERT ON catalogo_asignacion TO app_rw;
        GRANT UPDATE (hasta) ON catalogo_asignacion TO app_rw;
    END IF;
END
$$
"""

REVOCAR_APP_RW = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        REVOKE ALL ON catalogo_finca, catalogo_parcela, catalogo_propiedad, catalogo_asignacion
        FROM app_rw;
    END IF;
END
$$
"""


class Migration(migrations.Migration):
    dependencies = [
        ("catalogo", "0001_initial"),
        ("usuarios", "0002_reglas_y_permisos"),
    ]

    operations = [
        migrations.RunSQL(sql=COLUMNA_GEOMETRIA, reverse_sql=QUITAR_COLUMNA_GEOMETRIA),
        migrations.RunSQL(
            sql=[FUNCION_SIN_TRASLAPE, TRIGGER_SIN_TRASLAPE],
            reverse_sql=[
                "DROP TRIGGER catalogo_parcela_sin_traslape ON catalogo_parcela",
                "DROP FUNCTION catalogo_parcela_sin_traslape()",
            ],
        ),
        migrations.RunSQL(
            sql=[FUNCION_TECNICO_R1, TRIGGER_TECNICO_R1],
            reverse_sql=[
                "DROP TRIGGER catalogo_asignacion_requiere_r1 ON catalogo_asignacion",
                "DROP FUNCTION catalogo_asignacion_requiere_r1()",
            ],
        ),
        migrations.RunSQL(sql=[PERMISOS_APP_RW], reverse_sql=[REVOCAR_APP_RW]),
    ]
