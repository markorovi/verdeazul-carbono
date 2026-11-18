"""Lectura del estado de las mediciones para las comprobaciones del catálogo (Cd15).

Solo PostgreSQL. Los servicios de catálogo deben saber si una parcela tiene mediciones en curso o un
certificado vigente, pero el administrador de catálogo (R3) no tiene rol de lectura de mediciones y
la RLS le oculta todas las filas: la comprobación pasaría siempre.

Esta política deja ver filas de mediciones_medicion solo dentro de una transacción que declaró
app.proposito = 'catalogo' (lo hace catalogo.servicios, solo para contar), con un actor declarado y
solo en estados que importan a Cd15. No toca versiones, aprobaciones, enmiendas ni certificados:
"certificada" equivale a tener un certificado vigente, porque la base solo emite sobre una medición
aprobada (y la pasa a certificada) y solo la saca de certificada al anular el certificado.
No es SECURITY DEFINER ni depende del rol del actor, así que falla cerrado igual para cualquiera.
"""

from django.db import migrations

POLITICA = """
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        CREATE POLICY medicion_estado_para_catalogo ON mediciones_medicion
            AS PERMISSIVE FOR SELECT TO app_rw
            USING (app_usuario_actual() IS NOT NULL
                   AND current_setting('app.proposito', true) = 'catalogo'
                   AND estado IN ('borrador', 'presentada', 'devuelta', 'aprobada', 'certificada'));
    END IF;
END
$$
"""

QUITAR_POLITICA = "DROP POLICY IF EXISTS medicion_estado_para_catalogo ON mediciones_medicion"


class Migration(migrations.Migration):
    dependencies = [
        ("mediciones", "0009_alertas_cuenta_afectada_y_resolucion"),
    ]

    operations = [
        migrations.RunSQL(sql=[POLITICA], reverse_sql=[QUITAR_POLITICA]),
    ]
