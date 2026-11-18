"""Destino de `next`: solo rutas internas de este sitio (sin redirección abierta)."""

from __future__ import annotations

import re

from django.urls import Resolver404, resolve

# Ruta absoluta interna: empieza con una sola barra y solo usa caracteres seguros de ruta y consulta.
_RUTA = re.compile(r"^/(?![/\\])[A-Za-z0-9/_.\-]*(\?[A-Za-z0-9=&_.\-%]*)?$")
DESTINO_POR_DEFECTO = "/cuenta/"


def destino_seguro(valor, defecto: str = DESTINO_POR_DEFECTO) -> str:
    """Devuelve `valor` si es una ruta interna que existe; si no, el destino por defecto.

    Rechaza esquemas, hosts, rutas que empiezan con // o con barra invertida, caracteres de control
    y cualquier ruta que no resuelva a una vista de este proyecto.
    """
    if not isinstance(valor, str) or len(valor) > 512 or not _RUTA.match(valor):
        return defecto
    try:
        resolve(valor.split("?", 1)[0])
    except Resolver404:
        return defecto
    return valor
