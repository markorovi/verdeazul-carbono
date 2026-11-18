"""Huella SHA-256 de una versión de medición.

Debe coincidir byte a byte con mediciones_calcular_huella() de la base (migración 0004):
campos unidos con "|", co2e con 3 decimales (como imprime PostgreSQL un numeric(14,3)),
fecha AAAA-MM-DD y vacío en lugar de nulo.
"""

import hashlib
from decimal import ROUND_HALF_UP, Decimal

TRES_DECIMALES = Decimal("0.001")


def formatear_co2e(co2e) -> str:
    # PostgreSQL redondea numeric alejándose de cero en el empate; ROUND_HALF_UP hace lo mismo.
    return format(Decimal(str(co2e)).quantize(TRES_DECIMALES, rounding=ROUND_HALF_UP), "f")


def calcular_huella(medicion_id, numero, co2e_toneladas, fecha_muestreo, notas, creada_por_id, huella_previa) -> str:
    partes = [
        str(medicion_id),
        str(numero),
        formatear_co2e(co2e_toneladas),
        fecha_muestreo.isoformat(),
        notas or "",
        str(creada_por_id),
        huella_previa or "",
    ]
    return hashlib.sha256("|".join(partes).encode("utf-8")).hexdigest()
