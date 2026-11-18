"""Contexto del actor para las políticas de fila (RLS) de la base."""

from contextlib import contextmanager

from django.db import connection, transaction


@contextmanager
def como_actor(usuario_id):
    """Abre una transacción y fija app.usuario_id solo dentro de ella (set_config local).

    Si se anida en otra transacción, el valor dura hasta que termine la transacción externa.
    """
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT set_config('app.usuario_id', %s, true)", [str(usuario_id)])
        yield
