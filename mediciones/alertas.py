"""Avisos y alertas: registro común de avisos y resolución de alertas (O8.Rs).

Todo aviso se registra con registrar_aviso, dentro de la transacción de la operación que lo origina:
si el aviso no se puede registrar, la operación tampoco ocurre (falla cerrado).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from django.db.models.functions import Now

from mediciones import transaccion
from mediciones.errores import NoEncontrado, ReglaIncumplida
from mediciones.models import Alerta
from usuarios.models import Usuario

AVISO = Alerta.Prioridad.AVISO
PRIORITARIA = Alerta.Prioridad.PRIORITARIA

TIPO_ANULACION_CERTIFICADO = "anulacion_certificado"
TIPO_ALTA_FINCA = "alta_finca"
TIPO_ALTA_PARCELA = "alta_parcela"
TIPO_CAMBIO_PROPIETARIOS = "cambio_propietarios"
TIPO_ASIGNACION_TECNICO = "asignacion_tecnico"

# Mismo mínimo que los demás motivos y justificaciones del sistema.
LARGO_MINIMO_JUSTIFICACION = 10

_RESTRICCIONES = {
    "alerta_resolucion_independiente": ("Cd18", "quien es parte de la alerta no la resuelve"),
}


@dataclass(frozen=True)
class AlertaResultado:
    alerta_id: uuid.UUID
    resuelta_en: datetime


def prioridad_para(actor_id, cuenta_afectada_id) -> str:
    """Prioritaria si quien opera también dio de alta la cuenta afectada; si no se sabe, normal."""
    if cuenta_afectada_id is None:
        return AVISO
    if Usuario.objects.filter(pk=cuenta_afectada_id, creado_por_id=actor_id).exists():
        return PRIORITARIA
    return AVISO


def registrar_aviso(tipo: str, actor_id, *, prioridad: str | None = None, cuenta_afectada_id=None,
                    parcela_id=None, medicion_id=None, detalle: dict | None = None) -> uuid.UUID:
    """Registro único de avisos. Sin prioridad explícita, la calcula prioridad_para."""
    alerta = Alerta.objects.create(
        tipo=tipo,
        prioridad=prioridad or prioridad_para(actor_id, cuenta_afectada_id),
        usuario_id=actor_id,
        cuenta_afectada_id=cuenta_afectada_id,
        parcela_id=parcela_id,
        medicion_id=medicion_id,
        detalle=detalle or {},
    )
    return alerta.pk


def _regla_de_la_base(error) -> ReglaIncumplida | None:
    sqlstate, diag = transaccion.diagnostico(error)
    if diag is None:
        return None
    if sqlstate == "23514" and diag.constraint_name in _RESTRICCIONES:
        return ReglaIncumplida(*_RESTRICCIONES[diag.constraint_name])
    if sqlstate == "23000" and (diag.message_primary or "").startswith("Alerta: ya fue resuelta"):
        return ReglaIncumplida("Cd18", "la alerta ya fue resuelta")
    return None


@transaccion.servicio(_regla_de_la_base)
def resolver_alerta(actor, alerta_id, *, justificacion: str) -> AlertaResultado:
    """Cd18: alerta pendiente, justificación suficiente y actor que no es parte de la alerta.

    Partes: quien originó el evento (usuario) y la cuenta afectada. Una alerta en la que el actor es
    parte (por ejemplo, la anulación que hizo un R7) la revisa la gerencia fuera del sistema. La base
    repite la independencia con una restricción CHECK y fija resuelta_en.
    """
    texto = (justificacion or "").strip()
    if len(texto) < LARGO_MINIMO_JUSTIFICACION:
        raise ReglaIncumplida("Cd18", "la justificación es obligatoria (10 caracteres como mínimo)")
    alerta = Alerta.objects.select_for_update().filter(pk=alerta_id).first()
    if alerta is None:
        raise NoEncontrado("La alerta no existe.")
    if alerta.resuelta_en is not None:
        raise ReglaIncumplida("Cd18", "la alerta ya fue resuelta")
    if actor.pk in {alerta.usuario_id, alerta.cuenta_afectada_id}:
        raise ReglaIncumplida("Cd18", "quien es parte de la alerta no la resuelve")
    Alerta.objects.filter(pk=alerta.pk).update(
        resuelta_en=Now(), resuelta_por_id=actor.pk, justificacion_resolucion=texto
    )
    resuelta_en = Alerta.objects.filter(pk=alerta.pk).values_list("resuelta_en", flat=True).get()
    return AlertaResultado(alerta.pk, resuelta_en)
