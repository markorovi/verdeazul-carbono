"""Códigos de un solo uso para el alta y la recuperación de cuentas (utilidades puras).

El código es aleatorio de 256 bits (secrets.token_urlsafe(32)); solo se guarda su SHA-256 y la
comparación es en tiempo constante. Un código de 256 bits no necesita un hash lento: no hay espacio
que recorrer por fuerza bruta, a diferencia de una contraseña.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from usuarios.models import MAX_INTENTOS_CODIGO, CodigoUnUso

BYTES_CODIGO = 32
# El alta da tiempo a que la persona reciba el código por un canal fuera del sistema; la
# recuperación es corta porque reemplaza una credencial de una cuenta que ya existe.
VIGENCIA_ALTA = timedelta(hours=24)
VIGENCIA_RECUPERACION = timedelta(minutes=30)

VIGENCIAS = {
    CodigoUnUso.Proposito.ALTA: VIGENCIA_ALTA,
    CodigoUnUso.Proposito.RECUPERACION: VIGENCIA_RECUPERACION,
}


def generar() -> str:
    return secrets.token_urlsafe(BYTES_CODIGO)


def huella(codigo: str) -> str:
    return hashlib.sha256(codigo.encode("utf-8")).hexdigest()


def coincide(huella_guardada: str, codigo: str) -> bool:
    return hmac.compare_digest(huella_guardada.encode("ascii"), huella(codigo).encode("ascii"))


def vigencia(proposito: str) -> timedelta:
    return VIGENCIAS[proposito]


def disponible(vence_en: datetime, usado_en: datetime | None, intentos_fallidos: int, ahora: datetime) -> bool:
    """Sin usar, con menos de MAX_INTENTOS_CODIGO fallos y antes de su vencimiento."""
    return usado_en is None and intentos_fallidos < MAX_INTENTOS_CODIGO and ahora < vence_en
