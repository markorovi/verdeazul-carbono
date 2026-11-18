"""Arranque local: python -m bitacora_svc [--puerto 8090]. Lee la configuración del entorno y escucha
solo en 127.0.0.1. Las llaves (BITACORA_SALT, BITACORA_SIGNING_KEY) deben venir del entorno; nunca
se imprimen."""

import argparse
import logging
import sys

from bitacora_svc.almacen import AlmacenNoDisponible
from bitacora_svc.app import crear_aplicacion
from bitacora_svc.claves import LlaveNoConfigurada
from bitacora_svc.servicio import Configuracion
from bitacora_svc.servidor import ServidorLocal


def main() -> int:
    parser = argparse.ArgumentParser(description="Servicio de bitácora (solo loopback).")
    parser.add_argument("--puerto", type=int, default=8090)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        configuracion = Configuracion.desde_entorno()
    except (LlaveNoConfigurada, AlmacenNoDisponible, ValueError) as error:
        print(f"[FALLO] {error}")
        return 2
    servidor = ServidorLocal(crear_aplicacion(configuracion), args.puerto).iniciar()
    print(f"Bitácora escuchando en {servidor.url} (Ctrl+C para detener)")
    try:
        servidor.esperar()
    except KeyboardInterrupt:
        servidor.detener()
    return 0


if __name__ == "__main__":
    sys.exit(main())
