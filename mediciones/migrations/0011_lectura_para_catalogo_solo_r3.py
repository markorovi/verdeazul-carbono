"""La lectura de estados para el catálogo exige además el rol R3 vigente del actor.

Solo PostgreSQL. Reemplaza el predicado de medicion_estado_para_catalogo (migración 0010): además
del actor declarado, del propósito 'catalogo' y de los estados que importan a Cd15, la sesión debe
corresponder a un administrador de catálogo (R3). Así, declarar el propósito no basta para ver
mediciones desde otro rol.

La RLS limita filas, no columnas: con el propósito declarado, un R3 podría leer cualquier columna de
mediciones_medicion en esos estados. Ningún servicio de catálogo expone esos datos: solo los cuenta
para decidir Cd15, y el propósito se retira en cuanto termina la consulta.
"""

from django.db import migrations

ESTADOS = "('borrador', 'presentada', 'devuelta', 'aprobada', 'certificada')"


def _alterar(con_r3: bool) -> str:
    rol = " AND app_tiene_rol('R3')" if con_r3 else ""
    return f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public'
                AND tablename = 'mediciones_medicion' AND policyname = 'medicion_estado_para_catalogo') THEN
        ALTER POLICY medicion_estado_para_catalogo ON mediciones_medicion
            USING (app_usuario_actual() IS NOT NULL{rol}
                   AND current_setting('app.proposito', true) = 'catalogo'
                   AND estado IN {ESTADOS});
    END IF;
END
$$
"""


class Migration(migrations.Migration):
    dependencies = [
        ("mediciones", "0010_lectura_para_catalogo"),
    ]

    operations = [
        migrations.RunSQL(sql=[_alterar(True)], reverse_sql=[_alterar(False)]),
    ]
