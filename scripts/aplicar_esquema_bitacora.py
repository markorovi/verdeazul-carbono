#!/usr/bin/env python3
"""Aplica bitacora_svc/esquema.sql en la base de bitácora de dev con la cuenta propietaria.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/aplicar_esquema_bitacora.py [--esquema bitacora]

Usa DATABASE_URL_BITACORA_MIGRADOR (bit_migrador), que solo carga entorno_dev.ps1 -Pruebas. Se niega
a correr fuera de ENTORNO=local o si existe VERDEAZUL_PROD. Si el esquema ya existe, no hace nada.
Nunca imprime cadenas de conexión.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bitacora_svc import esquema as esquemas  # noqa: E402

VARIABLE = "DATABASE_URL_BITACORA_MIGRADOR"
PATRON_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")


def main() -> int:
    parser = argparse.ArgumentParser(description="Aplica el esquema de la bitácora en dev.")
    parser.add_argument("--esquema", default=esquemas.ESQUEMA_POR_DEFECTO)
    args = parser.parse_args()
    if os.environ.get("ENTORNO") != "local" or "VERDEAZUL_PROD" in os.environ:
        print("[FALLO] Solo corre con ENTORNO=local y sin VERDEAZUL_PROD.")
        return 2
    url = os.environ.get(VARIABLE)
    if not url:
        print(f"[FALLO] Falta {VARIABLE}. Cargue antes: . .\\scripts\\entorno_dev.ps1 -Pruebas")
        return 2
    nombre = esquemas.validar_nombre(args.esquema)
    try:
        with psycopg.connect(url, connect_timeout=15) as conexion:
            usuario = conexion.execute("SELECT current_user").fetchone()[0]
            existe = conexion.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s", [nombre]).fetchone()
        print(f"Conectado como {usuario}.")
        if existe:
            print(f"[OK] El esquema {nombre} ya existe; no se modifica.")
            return 0
        esquemas.aplicar(url, nombre)
    except psycopg.Error as error:
        detalle = PATRON_URL.sub("[REDACTADO]", (error.diag.message_primary or type(error).__name__) if error.diag else type(error).__name__)
        print(f"[FALLO] {error.sqlstate or '-'} {detalle}")
        return 1
    print(f"[OK] Esquema {nombre} aplicado.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
