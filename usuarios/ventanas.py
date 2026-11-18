"""Conteo de días de las ventanas de auditoría por año calendario (utilidades puras).

Los días se cuentan como duración real: segundos de la ventana / 86400, sin redondear. Una ventana
que cruza el cambio de año suma a cada año solo la parte que cae dentro de él (fechas UTC, la
TIME_ZONE del proyecto). El límite se compara en segundos para no acumular errores de redondeo.
"""

from __future__ import annotations

from datetime import datetime, timezone

SEGUNDOS_POR_DIA = 86400


def _inicio_de_anio(anio: int) -> datetime:
    return datetime(anio, 1, 1, tzinfo=timezone.utc)


def segundos_por_anio(inicio: datetime, fin: datetime) -> dict[int, int]:
    """Segundos de [inicio, fin) que caen en cada año calendario UTC."""
    inicio, fin = inicio.astimezone(timezone.utc), fin.astimezone(timezone.utc)
    resultado: dict[int, int] = {}
    cursor = inicio
    while cursor < fin:
        corte = min(fin, _inicio_de_anio(cursor.year + 1))
        resultado[cursor.year] = resultado.get(cursor.year, 0) + int((corte - cursor).total_seconds())
        cursor = corte
    return resultado


def excede_limite(existentes, nueva: tuple[datetime, datetime], dias_anuales: int) -> bool:
    """True si sumar la ventana nueva lleva algún año por encima de dias_anuales días."""
    acumulado: dict[int, int] = {}
    for inicio, fin in existentes:
        for anio, segundos in segundos_por_anio(inicio, fin).items():
            acumulado[anio] = acumulado.get(anio, 0) + segundos
    limite = dias_anuales * SEGUNDOS_POR_DIA
    return any(
        acumulado.get(anio, 0) + segundos > limite for anio, segundos in segundos_por_anio(*nueva).items()
    )
