"""Ajustes de seguridad propios del proyecto."""

import re

from django.views.debug import SafeExceptionReporterFilter


class FiltroReporteSeguro(SafeExceptionReporterFilter):
    """Oculta en los reportes de error, además de lo habitual, todo lo que contenga DATABASE.

    Cubre variables como DATABASE_URL, que con runserver llegan en request.META y que el
    filtro por defecto de Django mostraría completas.
    """

    hidden_settings = re.compile(
        "API|AUTH|TOKEN|KEY|PASS|SECRET|SIGNATURE|HTTP_COOKIE|DATABASE",
        re.IGNORECASE,
    )
