"""Intentos fallidos por origen (IP seudonimizada), para el límite de acceso y de recuperación.

El bloqueo por cuenta (usuarios.autenticacion) no frena a quien prueba muchas cuentas desde una
misma IP: esta tabla cuenta los fallos por origen. La IP no se guarda: se guarda su HMAC-SHA256 con
SECRET_KEY. Las filas son de solo anexar (sin UPDATE ni DELETE para app_rw) y el sello lo fija la
base con now(). Retención: 30 días por política; la depuración la hace el dueño de la base.
"""

from django.db import models
from django.db.models import Q
from django.db.models.functions import Now

from usuarios.models import ModeloConUUID

AMBITOS = ["acceso", "recuperacion"]


class IntentoFallido(ModeloConUUID):
    class Ambito(models.TextChoices):
        ACCESO = "acceso", "Acceso"
        RECUPERACION = "recuperacion", "Recuperación"

    ambito = models.CharField(max_length=15, choices=Ambito.choices)
    origen = models.CharField(max_length=64)
    sello = models.DateTimeField(db_default=Now())

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(ambito__in=AMBITOS), name="intentofallido_ambito_valido"),
            models.CheckConstraint(condition=Q(origen__regex=r"^[0-9a-f]{64}$"), name="intentofallido_origen_hex"),
        ]
        indexes = [models.Index(fields=["ambito", "origen", "sello"], name="intentofallido_origen_sello")]
