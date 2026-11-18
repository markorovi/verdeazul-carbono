"""Fincas, parcelas, propiedad y asignación de técnicos.

Las bajas son lógicas (dada_de_baja_en); nunca se borra. La geometría de la parcela vive en la
columna geom, creada por SQL en las migraciones y manejada con catalogo.geometria.
"""

from django.conf import settings
from django.db import models
from django.db.models import F, Q
from django.utils import timezone

from usuarios.models import ModeloConUUID


class Finca(ModeloConUUID):
    nombre = models.CharField(max_length=200)
    creada_en = models.DateTimeField(default=timezone.now)
    dada_de_baja_en = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.nombre


class Parcela(ModeloConUUID):
    """Parcela de una finca. Se crea con catalogo.geometria.crear_parcela (geom es obligatoria)."""

    finca = models.ForeignKey(Finca, on_delete=models.PROTECT, related_name="parcelas")
    codigo = models.CharField(max_length=50)
    dada_de_baja_en = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["finca", "codigo"], name="parcela_codigo_unico_por_finca"),
        ]

    def __str__(self):
        return self.codigo


class Propiedad(ModeloConUUID):
    """Relación dueño-finca. Vigente mientras `hasta` sea NULL."""

    dueno = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    finca = models.ForeignKey(Finca, on_delete=models.PROTECT, related_name="propiedades")
    desde = models.DateTimeField(default=timezone.now)
    hasta = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["dueno", "finca"],
                condition=Q(hasta__isnull=True),
                name="propiedad_vigente_unica",
            ),
        ]


class Asignacion(ModeloConUUID):
    """Asignación de un técnico (R1 vigente) a una parcela, siempre con vencimiento."""

    tecnico = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    parcela = models.ForeignKey(Parcela, on_delete=models.PROTECT, related_name="asignaciones")
    desde = models.DateTimeField(default=timezone.now)
    hasta = models.DateTimeField()

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(hasta__gt=F("desde")), name="asignacion_hasta_posterior"),
        ]
