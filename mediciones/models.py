"""Períodos de medición (globales, no por finca).

Un trigger de la migración impide borrar períodos y solo permite cerrarlos una vez:
el cierre es irreversible.
"""

from django.conf import settings
from django.db import models
from django.db.models import F, Q

from usuarios.models import ModeloConUUID


class Periodo(ModeloConUUID):
    class Estado(models.TextChoices):
        ABIERTO = "abierto", "Abierto"
        CERRADO = "cerrado", "Cerrado"

    inicio = models.DateField()
    fin = models.DateField()
    estado = models.CharField(max_length=10, choices=Estado.choices, default=Estado.ABIERTO)
    cerrado_en = models.DateTimeField(null=True, blank=True)
    cerrado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(fin__gt=F("inicio")), name="periodo_fin_posterior"),
            models.CheckConstraint(
                condition=Q(estado__in=["abierto", "cerrado"]), name="periodo_estado_valido"
            ),
            models.CheckConstraint(
                condition=(Q(estado="abierto") & Q(cerrado_en__isnull=True))
                | (Q(estado="cerrado") & Q(cerrado_en__isnull=False)),
                name="periodo_cierre_coherente",
            ),
        ]
