"""Roles, exclusiones estáticas, trigger de separación de funciones y permisos de app_rw.

Solo PostgreSQL. Se ejecuta con el rol migrador, que queda como dueño de los objetos.
"""

from django.db import migrations

ROLES = [
    ("R1", "Técnico de Campo"),
    ("R2", "Verificador"),
    ("R3", "Administrador de Catálogo"),
    ("R4", "Administrador de Cuentas"),
    ("R5", "Auditor Externo"),
    ("R6", "Dueño de Finca"),
    ("R7", "Responsable de Certificación"),
]

# Tabla 10 del P1: 19 pares incompatibles. Sin excluir: R1-R3 y R3-R4 (excepción con
# control compensatorio).
EXCLUSIONES = [
    ("R1", "R2"), ("R1", "R7"), ("R2", "R7"), ("R3", "R7"), ("R2", "R3"),
    ("R1", "R4"), ("R2", "R4"), ("R4", "R7"), ("R1", "R5"), ("R2", "R5"),
    ("R3", "R5"), ("R4", "R5"), ("R5", "R6"), ("R5", "R7"), ("R1", "R6"),
    ("R2", "R6"), ("R3", "R6"), ("R4", "R6"), ("R6", "R7"),
]

FUNCION_EXCLUSION = """
CREATE FUNCTION usuarios_rolusuario_exclusion() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
    rol_en_conflicto varchar(2);
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext(NEW.usuario_id::text));
    SELECT ru.rol_id INTO rol_en_conflicto
      FROM usuarios_rolusuario ru
      JOIN usuarios_exclusionestatica ex
        ON ex.rol_a_id = LEAST(ru.rol_id, NEW.rol_id)
       AND ex.rol_b_id = GREATEST(ru.rol_id, NEW.rol_id)
     WHERE ru.usuario_id = NEW.usuario_id
       AND ru.hasta IS NULL
       AND ru.id <> NEW.id
     LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'integrity_constraint_violation',
            MESSAGE = format(
                'Separación de funciones: el rol %s es incompatible con el rol vigente %s'
                ' del mismo usuario (exclusión estática).',
                NEW.rol_id, rol_en_conflicto);
    END IF;
    RETURN NEW;
END;
$$
"""

TRIGGER_EXCLUSION = """
CREATE TRIGGER usuarios_rolusuario_exclusion
BEFORE INSERT OR UPDATE ON usuarios_rolusuario
FOR EACH ROW
WHEN (NEW.hasta IS NULL)
EXECUTE FUNCTION usuarios_rolusuario_exclusion()
"""

PERMISOS_APP_RW = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        GRANT SELECT, INSERT ON usuarios_usuario TO app_rw;
        GRANT UPDATE (password, last_login, nombre, activo) ON usuarios_usuario TO app_rw;
        GRANT SELECT ON usuarios_rol TO app_rw;
        GRANT SELECT, INSERT ON usuarios_rolusuario TO app_rw;
        GRANT UPDATE (hasta) ON usuarios_rolusuario TO app_rw;
        GRANT SELECT ON usuarios_exclusionestatica TO app_rw;
        GRANT SELECT, INSERT ON usuarios_ventanaauditoria TO app_rw;
        GRANT SELECT, INSERT ON usuarios_accesoemergencia TO app_rw;
        GRANT UPDATE (usado_en, revisado_en) ON usuarios_accesoemergencia TO app_rw;
        GRANT SELECT, INSERT, UPDATE, DELETE ON django_session TO app_rw;
        GRANT SELECT ON django_migrations TO app_rw;
    END IF;
END
$$
"""

REVOCAR_APP_RW = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        REVOKE ALL ON usuarios_usuario, usuarios_rol, usuarios_rolusuario,
            usuarios_exclusionestatica, usuarios_ventanaauditoria, usuarios_accesoemergencia,
            django_session, django_migrations
        FROM app_rw;
    END IF;
END
$$
"""


class Migration(migrations.Migration):
    dependencies = [
        ("usuarios", "0001_initial"),
        ("sessions", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[
                ("INSERT INTO usuarios_rol (codigo, nombre) VALUES (%s, %s)", [codigo, nombre])
                for codigo, nombre in ROLES
            ],
            reverse_sql=["DELETE FROM usuarios_rol"],
        ),
        migrations.RunSQL(
            sql=[
                ("INSERT INTO usuarios_exclusionestatica (rol_a_id, rol_b_id) VALUES (%s, %s)", [a, b])
                for a, b in EXCLUSIONES
            ],
            reverse_sql=["DELETE FROM usuarios_exclusionestatica"],
        ),
        migrations.RunSQL(
            sql=[FUNCION_EXCLUSION, TRIGGER_EXCLUSION],
            reverse_sql=[
                "DROP TRIGGER usuarios_rolusuario_exclusion ON usuarios_rolusuario",
                "DROP FUNCTION usuarios_rolusuario_exclusion()",
            ],
        ),
        migrations.RunSQL(sql=[PERMISOS_APP_RW], reverse_sql=[REVOCAR_APP_RW]),
    ]
