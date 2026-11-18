"""Aplicación del esquema de bitácora con la cuenta propietaria de esa base (bit_migrador).

Nunca lo usa el servicio: solo scripts/aplicar_esquema_bitacora.py y las pruebas, que crean un
esquema temporal por corrida y lo destruyen al final (la tabla es de solo anexar y sus filas no se
pueden borrar una a una). Solo se destruyen esquemas con el prefijo de prueba.
"""

from __future__ import annotations

import re
from pathlib import Path

import psycopg
from psycopg import sql

RUTA_ESQUEMA = Path(__file__).resolve().parent / "esquema.sql"
ESQUEMA_POR_DEFECTO = "bitacora"
PREFIJO_PRUEBA = "bitacora_prueba_"
_NOMBRE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")


def validar_nombre(esquema: str) -> str:
    if not _NOMBRE.fullmatch(esquema or "") or esquema.startswith("pg_") or esquema == "public":
        raise ValueError("Nombre de esquema inválido.")
    return esquema


def sql_del_esquema(esquema: str) -> str:
    return RUTA_ESQUEMA.read_text(encoding="utf-8").replace("__ESQUEMA__", validar_nombre(esquema))


def aplicar(url_propietario: str, esquema: str = ESQUEMA_POR_DEFECTO) -> None:
    """Crea el esquema completo en una sola transacción; si algo falla, no queda nada."""
    texto = sql_del_esquema(esquema)
    with psycopg.connect(url_propietario, connect_timeout=15, autocommit=False) as conexion:
        conexion.execute(texto)
        conexion.commit()


def destruir_prueba(url_propietario: str, esquema: str) -> None:
    if not validar_nombre(esquema).startswith(PREFIJO_PRUEBA):
        raise ValueError("Solo se destruyen esquemas de prueba.")
    with psycopg.connect(url_propietario, connect_timeout=15, autocommit=True) as conexion:
        conexion.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(esquema)))
