"""Parámetros de política y cálculo de plazos de los servicios de mediciones.

Los umbrales y plazos se leen siempre de PoliticaParametro; aquí no hay valores fijos de negocio.
Los días hábiles son de lunes a viernes, sin feriados, sobre fechas UTC (TIME_ZONE del proyecto).
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from decimal import Decimal

from mediciones.errores import ParametroNoConfigurado
from mediciones.models import PoliticaParametro

CLAVE_VALTO = "valto_tco2e"
CLAVE_PLAZO_ENMIENDA = "tenm_dias"
# Plazo de verificación (Cd19). No está sembrado por las migraciones 0001 a 0006: mientras falte, la
# reasignación por plazo falla cerrada con ParametroNoConfigurado.
CLAVE_PLAZO_VERIFICACION = "tver_dias_habiles"

SABADO = 5


def leer_parametro(clave: str) -> Decimal:
    valor = PoliticaParametro.objects.filter(clave=clave).values_list("valor", flat=True).first()
    if valor is None:
        raise ParametroNoConfigurado(f"Falta el parámetro de política {clave}.")
    return valor


def leer_parametro_entero(clave: str) -> int:
    """Para plazos en días: un valor con decimales o no positivo es un error de configuración."""
    valor = leer_parametro(clave)
    if valor != valor.to_integral_value() or valor <= 0:
        raise ParametroNoConfigurado(f"El parámetro de política {clave} debe ser un entero positivo.")
    return int(valor)


def fecha_utc(momento: datetime) -> date:
    return momento.astimezone(timezone.utc).date()


def dias_habiles_entre(desde: date, hasta: date) -> int:
    """Días de lunes a viernes en (desde, hasta]: el día de inicio no cuenta y el final sí."""
    if hasta <= desde:
        return 0
    total = (hasta - desde).days
    semanas, resto = divmod(total, 7)
    dias = semanas * 5
    for desplazamiento in range(1, resto + 1):
        if (desde + timedelta(days=desplazamiento)).weekday() < SABADO:
            dias += 1
    return dias


def plazo_habil_vencido(desde: datetime, momento: datetime, dias_habiles: int) -> bool:
    """El plazo vence cuando ya pasaron más de dias_habiles días hábiles completos desde `desde`."""
    return dias_habiles_entre(fecha_utc(desde), fecha_utc(momento)) > dias_habiles


def enmienda_en_plazo(cerrado_en: datetime, momento: datetime, dias: int, certificado_anulado_sin_vigente: bool) -> bool:
    """Cd11 y Cd12: a lo sumo `dias` días desde el cierre, o un certificado anulado sin otro vigente.

    En la solicitud `momento` es la hora actual; al resolver es la fecha de la solicitud, de modo que
    una autorización tardía no invalida una solicitud hecha a tiempo.
    """
    return momento - cerrado_en <= timedelta(days=dias) or certificado_anulado_sin_vigente
