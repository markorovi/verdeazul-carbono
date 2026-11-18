"""Acceso a la geometría de las parcelas (columna geom, Polygon en SRID 5367 / CRTM05).

No usa django.contrib.gis ni GDAL: el WKT viaja como parámetro y PostGIS lo interpreta.
"""

import uuid

from django.db import connection


def crear_parcela(finca_id, codigo, wkt):
    """Inserta una parcela con su polígono en WKT y devuelve su id (UUID)."""
    parcela_id = uuid.uuid4()
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO catalogo_parcela (id, finca_id, codigo, geom)"
            " VALUES (%s, %s, %s, ST_GeomFromText(%s, 5367))",
            [parcela_id, finca_id, codigo, wkt],
        )
    return parcela_id


def limites_distintos(parcela_id, wkt):
    """True si el polígono en WKT no es geométricamente igual al de la parcela."""
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT NOT ST_Equals(geom, ST_GeomFromText(%s, 5367)) FROM catalogo_parcela WHERE id = %s",
            [wkt, parcela_id],
        )
        fila = cursor.fetchone()
    return bool(fila and fila[0])


def actualizar_limites(parcela_id, wkt):
    """Reemplaza el polígono; el disparador de la base rechaza los traslapes."""
    with connection.cursor() as cursor:
        cursor.execute(
            "UPDATE catalogo_parcela SET geom = ST_GeomFromText(%s, 5367) WHERE id = %s",
            [wkt, parcela_id],
        )


def obtener_parcela_wkt(parcela_id):
    """Devuelve el polígono de la parcela en WKT, o None si no existe."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT ST_AsText(geom) FROM catalogo_parcela WHERE id = %s", [parcela_id])
        fila = cursor.fetchone()
    return fila[0] if fila else None
