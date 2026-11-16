"""Pruebas del proyecto que no necesitan base de datos."""

import sys

from django.test import RequestFactory, SimpleTestCase
from django.views.debug import (
    ExceptionReporter,
    SafeExceptionReporterFilter,
    get_default_exception_reporter_filter,
)

VALOR_FALSO = "valor-falso-de-prueba"


def html_reporte_error(filtro=None) -> str:
    """HTML del reporte técnico de error para un request con DATABASE_URL en META.

    Si se indica `filtro`, se usa ese filtro para el request en lugar del configurado.
    """
    request = RequestFactory().get("/")
    request.META["DATABASE_URL"] = VALOR_FALSO
    if filtro is not None:
        request.exception_reporter_filter = filtro
    try:
        raise RuntimeError("error de prueba")
    except RuntimeError:
        reporte = ExceptionReporter(request, *sys.exc_info())
    return reporte.get_traceback_html()


class FiltroReporteSeguroTests(SimpleTestCase):
    def setUp(self):
        # Django guarda en caché el filtro por defecto; se limpia para leer la configuración actual.
        get_default_exception_reporter_filter.cache_clear()

    def test_oculta_database_url_en_el_reporte(self):
        self.assertNotIn(VALOR_FALSO, html_reporte_error())

    def test_el_filtro_estandar_lo_mostraria(self):
        """Control: con el filtro estándar de Django el valor sí aparece."""
        self.assertIn(VALOR_FALSO, html_reporte_error(SafeExceptionReporterFilter()))
