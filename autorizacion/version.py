"""Versión de la política: SHA-256 de la matriz, las constantes y la política Rego.

Fórmula: SHA-256 sobre, en este orden y para cada archivo, su nombre relativo en UTF-8, un salto de
línea, el largo en bytes en decimal, un salto de línea y sus bytes. Incluir nombre y largo evita que
dos combinaciones distintas de contenidos den la misma concatenación. Los finales de línea se
normalizan a LF para que Windows y el contenedor den la misma versión. Va en todos los eventos de
bitácora; cambia con cualquier cambio de la matriz, de las constantes o del Rego.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ARCHIVOS = ("autorizacion/matriz.json", "autorizacion/politica.json", "policy/autorizacion.rego")


def calcular(raiz: Path = RAIZ) -> str:
    total = hashlib.sha256()
    for nombre in ARCHIVOS:
        contenido = (raiz / nombre).read_bytes().replace(b"\r\n", b"\n")
        total.update(nombre.encode("utf-8") + b"\n" + str(len(contenido)).encode("ascii") + b"\n" + contenido)
    return total.hexdigest()


@lru_cache(maxsize=1)
def version_politica() -> str:
    return calcular()
