"""Almacén WORM de los puntos de control.

Un objeto por punto, puntos/{seq con 12 dígitos}.json, que se crea una sola vez y nunca se
sobrescribe. Backends:
- local: un directorio, con creación exclusiva del archivo (dev y pruebas);
- gcs: un bucket de Cloud Storage, con precondición if_generation_match=0 (el objeto no debe
  existir). La retención bloqueada se configura en el bucket, fuera del código.
"""

from __future__ import annotations

import os
from pathlib import Path


class YaExiste(Exception):
    """El punto ya está en el almacén; no se sobrescribe."""


class AlmacenNoDisponible(Exception):
    """El almacén falló. El mensaje no incluye credenciales."""


def nombre_de(seq: int) -> str:
    return f"puntos/{seq:012d}.json"


class AlmacenLocal:
    nombre = "local"

    def __init__(self, directorio: str | os.PathLike):
        self.raiz = Path(directorio)

    def guardar(self, seq: int, contenido: bytes) -> None:
        ruta = self.raiz / nombre_de(seq)
        try:
            ruta.parent.mkdir(parents=True, exist_ok=True)
            with open(ruta, "xb") as archivo:
                archivo.write(contenido)
        except FileExistsError:
            raise YaExiste(nombre_de(seq)) from None
        except OSError as error:
            raise AlmacenNoDisponible(f"no se pudo escribir el punto ({type(error).__name__})") from None

    def leer(self, seq: int) -> bytes | None:
        ruta = self.raiz / nombre_de(seq)
        try:
            return ruta.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise AlmacenNoDisponible(f"no se pudo leer el punto ({type(error).__name__})") from None

    def listar(self) -> list[int]:
        carpeta = self.raiz / "puntos"
        if not carpeta.exists():
            return []
        return sorted(int(r.stem) for r in carpeta.glob("*.json") if r.stem.isdigit())


class AlmacenGCS:
    nombre = "gcs"

    def __init__(self, bucket: str):
        if not bucket:
            raise AlmacenNoDisponible("falta el nombre del bucket")
        # Importación tardía: en dev y en pruebas no hace falta google-cloud-storage.
        from google.cloud import storage

        self._bucket = storage.Client().bucket(bucket)

    def guardar(self, seq: int, contenido: bytes) -> None:
        from google.api_core import exceptions

        try:
            self._bucket.blob(nombre_de(seq)).upload_from_string(
                contenido, content_type="application/json", if_generation_match=0
            )
        except exceptions.PreconditionFailed:
            raise YaExiste(nombre_de(seq)) from None
        except Exception as error:
            raise AlmacenNoDisponible(f"no se pudo escribir el punto ({type(error).__name__})") from None

    def leer(self, seq: int) -> bytes | None:
        from google.api_core import exceptions

        try:
            return self._bucket.blob(nombre_de(seq)).download_as_bytes()
        except exceptions.NotFound:
            return None
        except Exception as error:
            raise AlmacenNoDisponible(f"no se pudo leer el punto ({type(error).__name__})") from None

    def listar(self) -> list[int]:
        try:
            nombres = [b.name for b in self._bucket.list_blobs(prefix="puntos/")]
        except Exception as error:
            raise AlmacenNoDisponible(f"no se pudo listar los puntos ({type(error).__name__})") from None
        return sorted(int(n[len("puntos/"):-len(".json")]) for n in nombres
                      if n.endswith(".json") and n[len("puntos/"):-len(".json")].isdigit())


def almacen_de(tipo: str, destino: str):
    if not destino:
        raise AlmacenNoDisponible("falta BITACORA_WORM_DESTINO (directorio o bucket)")
    if tipo == "local":
        return AlmacenLocal(destino)
    if tipo == "gcs":
        return AlmacenGCS(destino)
    raise AlmacenNoDisponible("BITACORA_WORM debe ser 'local' o 'gcs'")
