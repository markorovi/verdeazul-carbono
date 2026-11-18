"""Excepciones de dominio de los servicios de mediciones.

Los mensajes son fijos y no incluyen datos de personas, valores medidos ni identificadores: la capa
que los muestre (vista, API o bitácora) decide qué agrega.
"""

from django.core.exceptions import ImproperlyConfigured


class ReglaIncumplida(Exception):
    """Una operación viola una condición de estado o de historial (Cd5, Cd6, Cd7, ...).

    condicion es estable (por ejemplo "Cd7") y sirve para decidir qué hacer; motivo es una frase
    corta para personas.
    """

    def __init__(self, condicion: str, motivo: str):
        super().__init__(f"{condicion}: {motivo}")
        self.condicion = condicion
        self.motivo = motivo


class NoEncontrado(Exception):
    """El objeto no existe o la RLS no lo deja ver al actor; no se distingue un caso del otro."""


class ParametroNoConfigurado(ImproperlyConfigured):
    """Falta un parámetro de política o su valor no sirve. Se falla cerrado, sin valores por defecto."""
