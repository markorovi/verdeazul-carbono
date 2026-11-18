"""Interfaz de la bitácora que usa el PEP. La implementación real (base separada, cadena de hashes)
llega después; aquí solo se define el contrato y un doble en memoria para las pruebas.

El PEP no arranca sin una bitácora configurada (BITACORA_CLIENTE): las condiciones Cd8, Cd10, Cd11,
Cd12, Cd17 y Cd20 dependen de que quede registro, así que sin ella esas operaciones se deniegan.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string


@runtime_checkable
class Bitacora(Protocol):
    def disponible(self) -> bool: ...

    def registrar(self, evento: dict) -> None: ...


class BitacoraNoDisponible(Exception):
    """El evento no se pudo registrar."""


class BitacoraEnMemoria:
    """Doble de pruebas. Con disponible=False simula la bitácora caída; con fallar_registro=True,
    que responde a disponible() pero no puede registrar.
    """

    def __init__(self, disponible: bool = True, fallar_registro: bool = False):
        self.esta_disponible = disponible
        self.fallar_registro = fallar_registro
        self.eventos: list[dict] = []

    def disponible(self) -> bool:
        return self.esta_disponible

    def registrar(self, evento: dict) -> None:
        if not self.esta_disponible or self.fallar_registro:
            raise BitacoraNoDisponible("La bitácora no está disponible.")
        self.eventos.append(dict(evento))


def bitacora_configurada() -> Bitacora:
    """Instancia la bitácora de BITACORA_CLIENTE (ruta a una clase o fábrica sin argumentos)."""
    ruta = getattr(settings, "BITACORA_CLIENTE", None)
    if not ruta:
        raise ImproperlyConfigured("Falta BITACORA_CLIENTE: el PEP no arranca sin bitácora.")
    bitacora = import_string(ruta)()
    if not isinstance(bitacora, Bitacora):
        raise ImproperlyConfigured("BITACORA_CLIENTE no implementa disponible() y registrar(evento).")
    return bitacora
