"""Transacción con actor para los servicios de dominio y traducción de los rechazos de la base."""

from __future__ import annotations

import functools
from datetime import datetime

from django.db import DatabaseError, connection, transaction

from mediciones.contexto import como_actor


def diagnostico(error: DatabaseError) -> tuple[str | None, object | None]:
    """SQLSTATE y diagnóstico del error de psycopg que originó el error de Django."""
    causa = error.__cause__
    return getattr(causa, "sqlstate", None), getattr(causa, "diag", None)


def servicio(traducir):
    """Decorador de servicio: transacción con el actor declarado; si algo falla no queda ningún cambio.

    `traducir` recibe el DatabaseError y devuelve la ReglaIncumplida equivalente, o None para que el
    error se propague tal cual.
    """

    def decorador(funcion):
        @functools.wraps(funcion)
        def envoltura(actor, *args, **kwargs):
            try:
                with transaction.atomic(), como_actor(actor.pk):
                    return funcion(actor, *args, **kwargs)
            except DatabaseError as error:
                regla = traducir(error)
                if regla is None:
                    raise
                raise regla from error

        return envoltura

    return decorador


def hora_de_la_base() -> datetime:
    with connection.cursor() as cursor:
        cursor.execute("SELECT now()")
        return cursor.fetchone()[0]
