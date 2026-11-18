"""Registro de intentos de lectura, fuente de los contadores de H2 (Cd9) y de las alertas por Cd2.

Retención: 24 meses, por política documentada; no hay purga automática. Las filas son inmutables
(disparadores) y la RLS deja a cada actor ver e insertar solo las suyas.
"""

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.db.models.functions import Now

from usuarios.models import ModeloConUUID

RESULTADOS = ["concedido", "denegado"]


class RegistroAcceso(ModeloConUUID):
    class Resultado(models.TextChoices):
        CONCEDIDO = "concedido", "Concedido"
        DENEGADO = "denegado", "Denegado"

    usuario = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    # Nula cuando el objeto no tiene parcela o la RLS no la deja ver al actor.
    parcela = models.ForeignKey(
        "catalogo.Parcela", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    operacion = models.CharField(max_length=10)
    ajena = models.BooleanField()
    resultado = models.CharField(max_length=10, choices=Resultado.choices)
    motivo = models.CharField(max_length=20, null=True, blank=True)
    # La base fija el sello con now() en un disparador; el valor del cliente se ignora.
    sello = models.DateTimeField(db_default=Now())

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(resultado__in=RESULTADOS), name="registroacceso_resultado_valido"),
        ]
        indexes = [models.Index(fields=["usuario", "sello"], name="registroacceso_usuario_sello")]
