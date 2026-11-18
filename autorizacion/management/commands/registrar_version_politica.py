"""Registra en la bitácora el cambio de versión de la política si difiere de la última registrada.

La versión es el SHA-256 de la matriz, las constantes y la política Rego (autorizacion.version).
"""

from django.core.management.base import BaseCommand, CommandError

from autorizacion.cliente_bitacora import ClienteBitacora
from autorizacion.version import calcular


class Command(BaseCommand):
    help = "Emite el evento de versión de política si cambió desde el último registrado."

    def add_arguments(self, parser):
        parser.add_argument("--url", help="URL del servicio (por defecto, BITACORA_URL)")

    def handle(self, *args, **opciones):
        version = calcular()
        try:
            cliente = ClienteBitacora(opciones.get("url"))
            ultimos = cliente.consultar(objeto_tipo="politica", orden="desc", limite=1)
            if ultimos and ultimos[0].get("objeto_id") == version:
                self.stdout.write(f"[OK] La versión {version[:16]} ya está registrada.")
                return
            cliente.registrar({
                "accion": "version_politica", "origen": "sistema", "resultado": "exito",
                "objeto_tipo": "politica", "objeto_id": version, "version_politica": version,
            })
        except Exception as error:
            raise CommandError(f"No se pudo registrar la versión de política ({type(error).__name__}).") from None
        self.stdout.write(f"[OK] Versión de política {version[:16]} registrada.")
