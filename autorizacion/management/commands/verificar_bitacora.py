"""Verifica la integridad de la bitácora (POST /verificar del servicio).

Si la cadena o los puntos de control fallan, o el servicio no responde, registra una alerta
prioritaria para R7 (tipo bitacora_integridad) con la función común de avisos. Es lo que ejecutará
un trabajo programado. Termina con código 1 si la bitácora no está íntegra.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from autorizacion.cliente_bitacora import ClienteBitacora
from mediciones import alertas

TIPO_INTEGRIDAD = "bitacora_integridad"


class Command(BaseCommand):
    help = "Verifica la cadena y los puntos de la bitácora; si fallan, alerta a R7."

    def add_arguments(self, parser):
        parser.add_argument("--url", help="URL del servicio (por defecto, BITACORA_URL)")

    def handle(self, *args, **opciones):
        try:
            resumen = ClienteBitacora(opciones.get("url")).verificar()
            integra, codigo, detalle = resumen.get("integra") is True, resumen.get("codigo"), resumen.get("detalle", "")
        except Exception as error:
            integra, codigo, detalle = False, None, f"el servicio no respondió ({type(error).__name__})"
        if integra:
            self.stdout.write(f"[OK] {detalle}")
            return
        with transaction.atomic():
            alertas.registrar_aviso(
                TIPO_INTEGRIDAD, None, prioridad=alertas.PRIORITARIA, detalle={"codigo": codigo, "detalle": detalle[:200]}
            )
        raise CommandError(f"Bitácora no íntegra (código {codigo}): {detalle}. Se registró una alerta para R7.")
