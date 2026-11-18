"""Límite de intentos fallidos por IP para el acceso y la recuperación.

Complementa el bloqueo por cuenta (5 fallos, 15 minutos): aquel frena a quien insiste con una
cuenta; este, a quien prueba muchas cuentas o códigos desde un mismo origen. Con LIMITE fallos en
VENTANA_MINUTOS el origen queda limitado (HTTP 429) hasta que los fallos salgan de la ventana; los
intentos limitados no se cuentan. La IP se toma con interfaz.red.ip_cliente y se guarda como HMAC.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque

from django.conf import settings
from django.db import connection, transaction

from interfaz.models import IntentoFallido
from interfaz.red import ip_cliente

ACCESO = IntentoFallido.Ambito.ACCESO
RECUPERACION = IntentoFallido.Ambito.RECUPERACION
LIMITE = 20
VENTANA_MINUTOS = 15

_CONTAR = (
    "SELECT count(*) FROM interfaz_intentofallido"
    " WHERE ambito = %s AND origen = %s AND sello > now() - make_interval(mins => %s)"
)


def origen(request) -> str:
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), ip_cliente(request).encode("utf-8"), hashlib.sha256).hexdigest()


def limitado(request, ambito: str) -> bool:
    """True si el origen ya llegó al límite. Si el conteo falla, se limita (falla cerrado)."""
    try:
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(_CONTAR, [ambito, origen(request), VENTANA_MINUTOS])
            return cursor.fetchone()[0] >= LIMITE
    except Exception:
        return True


def registrar_fallo(request, ambito: str) -> None:
    with transaction.atomic():
        IntentoFallido.objects.create(ambito=ambito, origen=origen(request))


class LimiteEnMemoria:
    """Límite de peticiones por origen para la verificación pública (sin sesión y sin escribir en
    la base). Es por proceso: con varias instancias el límite efectivo se multiplica; basta para
    frenar el abuso de CPU, que es lo que protege. Guarda solo el HMAC del origen."""

    def __init__(self, limite: int, ventana_segundos: float, maximo_origenes: int = 10000):
        self.limite = limite
        self.ventana = ventana_segundos
        self.maximo_origenes = maximo_origenes
        self._marcas: dict[str, deque] = {}
        self._candado = threading.Lock()

    def permitir(self, request) -> bool:
        clave = origen(request)
        ahora = time.monotonic()
        with self._candado:
            marcas = self._marcas.setdefault(clave, deque())
            while marcas and ahora - marcas[0] > self.ventana:
                marcas.popleft()
            if len(marcas) >= self.limite:
                return False
            marcas.append(ahora)
            if len(self._marcas) > self.maximo_origenes:
                for vieja in [c for c, m in self._marcas.items() if not m or ahora - m[-1] > self.ventana]:
                    self._marcas.pop(vieja, None)
            return True

    def reiniciar(self) -> None:
        with self._candado:
            self._marcas.clear()


VERIFICACION = LimiteEnMemoria(limite=30, ventana_segundos=300)
