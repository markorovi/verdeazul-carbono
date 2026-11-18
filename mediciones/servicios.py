"""Servicios del dominio de mediciones: períodos, mediciones, verificación, certificados y enmiendas.

Cada servicio recibe primero al actor (Usuario), corre en una transacción con el actor declarado para
la RLS (como_actor) y hace cumplir las condiciones de estado e historial: Cd5, Cd6, Cd7, Cd8, Cd10,
Cd11, Cd12, Cd19 y Cd20. Una violación lanza ReglaIncumplida y revierte todo lo hecho en el servicio.

Quién puede invocar cada servicio (roles, vínculos, ventana de auditoría, segundo factor, umbrales de
lectura) lo decide la capa de autorización, no este módulo. Los disparadores y la RLS de la base
repiten las reglas críticas: si la base rechaza algo con una condición conocida, se traduce a
ReglaIncumplida; cualquier otro error de base se propaga tal cual.

Bloqueos, siempre en este orden para evitar interbloqueos: período, medición, certificado y, al
resolver, enmienda. El período se toma FOR SHARE (impide cerrarlo a mitad de una operación sin
serializar todo el período) salvo al cerrarlo, que se toma FOR UPDATE.
"""

from __future__ import annotations

import functools
import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal

from django.db import DatabaseError, connection, transaction
from django.db.models import Count
from django.db.models.functions import Now

from mediciones import firma, plazos
from mediciones.contexto import como_actor
from mediciones.errores import NoEncontrado, ReglaIncumplida
from mediciones.models import (
    Alerta,
    Aprobacion,
    Certificado,
    Enmienda,
    Medicion,
    MedicionVersion,
    Periodo,
)
from usuarios.models import RolUsuario

ABIERTO = Periodo.Estado.ABIERTO
CERRADO = Periodo.Estado.CERRADO
BORRADOR = Medicion.Estado.BORRADOR
PRESENTADA = Medicion.Estado.PRESENTADA
DEVUELTA = Medicion.Estado.DEVUELTA
APROBADA = Medicion.Estado.APROBADA
CERTIFICADA = Medicion.Estado.CERTIFICADA
SIN_PRESENTAR = Medicion.Estado.SIN_PRESENTAR
VIGENTE = Certificado.Estado.VIGENTE
ANULADO = Certificado.Estado.ANULADO
SOLICITADA = Enmienda.Estado.SOLICITADA
AUTORIZADA = Enmienda.Estado.AUTORIZADA
RECHAZADA = Enmienda.Estado.RECHAZADA

# Mismo mínimo que las restricciones CHECK de la base para motivos y justificaciones.
LARGO_MINIMO_TEXTO = 10
ROL_VERIFICADOR = "R2"
TIPO_AVISO_ANULACION = "anulacion_certificado"
# La base calcula la huella de cada versión; este valor solo ocupa la columna en el INSERT.
HUELLA_PROVISIONAL = "0" * 64

CAUSA_SIN_ASIGNAR = "sin_verificador_asignado"
CAUSA_CD8 = "verificador_asignado_impedido_por_cd8"
CAUSA_PLAZO = "plazo_de_verificacion_vencido"

# Restricciones únicas que la base usa como última barrera ante operaciones simultáneas.
_RESTRICCIONES = {
    "certificado_vigente_unico": ("Cd10", "ya existe un certificado vigente para la parcela y el período"),
    "aprobacion_unica_por_ciclo": ("Cd8", "el actor ya aprobó la medición en este ciclo"),
    "enmienda_una_solicitada": ("Cd11", "la medición ya tiene una enmienda solicitada"),
}
_CONDICION_EN_MENSAJE = re.compile(r"\((?:H1, )?(Cd\d+)\)")


# --------------------------------------------------------------------------- resultados


@dataclass(frozen=True)
class MedicionResultado:
    medicion_id: uuid.UUID
    estado: str
    ciclo: int
    version_numero: int
    huella: str


@dataclass(frozen=True)
class AprobacionResultado:
    medicion_id: uuid.UUID
    estado: str
    ciclo: int
    aprobaciones: int
    aprobaciones_requeridas: int
    certificado_id: uuid.UUID | None


@dataclass(frozen=True)
class EstadoMedicion:
    medicion_id: uuid.UUID
    estado: str
    ciclo: int


@dataclass(frozen=True)
class ReasignacionResultado:
    medicion_id: uuid.UUID
    causa: str


@dataclass(frozen=True)
class PeriodoResultado:
    periodo_id: uuid.UUID
    estado: str
    cerrado_en: datetime | None
    sin_presentar: int
    en_verificacion: int


@dataclass(frozen=True)
class AnulacionResultado:
    certificado_id: uuid.UUID
    estado: str
    medicion_id: uuid.UUID
    medicion_estado: str
    ciclo: int


@dataclass(frozen=True)
class ExportacionResultado:
    certificado_id: uuid.UUID
    contenido: bytes
    huella_sha256: str


@dataclass(frozen=True)
class EnmiendaResultado:
    enmienda_id: uuid.UUID
    estado: str
    medicion_id: uuid.UUID
    medicion_estado: str
    ciclo: int
    version_numero: int | None


# --------------------------------------------------------------------------- infraestructura


def _regla_de_la_base(error: DatabaseError) -> ReglaIncumplida | None:
    """Traduce los rechazos de la base que corresponden a una condición conocida."""
    causa = error.__cause__
    diag = getattr(causa, "diag", None)
    if diag is None:
        return None
    sqlstate = getattr(causa, "sqlstate", None)
    if sqlstate == "23505" and diag.constraint_name in _RESTRICCIONES:
        return ReglaIncumplida(*_RESTRICCIONES[diag.constraint_name])
    if sqlstate == "23000":
        coincidencia = _CONDICION_EN_MENSAJE.search(diag.message_primary or "")
        if coincidencia:
            return ReglaIncumplida(coincidencia.group(1), "la base de datos rechazó la operación")
    return None


def _servicio(funcion):
    """Transacción con el actor declarado; si algo falla no queda ningún cambio del servicio."""

    @functools.wraps(funcion)
    def envoltura(actor, *args, **kwargs):
        try:
            with transaction.atomic(), como_actor(actor.pk):
                return funcion(actor, *args, **kwargs)
        except DatabaseError as error:
            regla = _regla_de_la_base(error)
            if regla is None:
                raise
            raise regla from error

    return envoltura


def _hora_de_la_base() -> datetime:
    with connection.cursor() as cursor:
        cursor.execute("SELECT now()")
        return cursor.fetchone()[0]


def _ahora() -> datetime:
    """Hora para los plazos. Las pruebas la sustituyen; la fecha de emisión no depende de ella."""
    return _hora_de_la_base()


def _periodo_compartido(periodo_id) -> tuple[str, datetime | None]:
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT estado, cerrado_en FROM mediciones_periodo WHERE id = %s FOR SHARE", [periodo_id]
        )
        fila = cursor.fetchone()
    if fila is None:
        raise NoEncontrado("El período no existe.")
    return fila[0], fila[1]


def _medicion_visible(medicion_id) -> Medicion:
    medicion = Medicion.objects.filter(pk=medicion_id).first()
    if medicion is None:
        raise NoEncontrado("La medición no existe o no es visible para el actor.")
    return medicion


def _medicion_bloqueada(medicion_id) -> Medicion:
    # La RLS de UPDATE también filtra el FOR UPDATE: sin permiso de escritura la fila no aparece.
    medicion = Medicion.objects.select_for_update().filter(pk=medicion_id).first()
    if medicion is None:
        raise NoEncontrado("La medición no existe o el actor no puede modificarla.")
    return medicion


def _version_vigente(medicion_id) -> MedicionVersion | None:
    return MedicionVersion.objects.filter(medicion_id=medicion_id).order_by("-numero").first()


def _autores(medicion: Medicion) -> set:
    """Quien registró o creó alguna versión (presentar solo lo hace quien registró)."""
    autores = {medicion.registrada_por_id}
    autores.update(
        MedicionVersion.objects.filter(medicion_id=medicion.pk).values_list("creada_por_id", flat=True)
    )
    return autores


def _impedidos_para_aprobar(medicion: Medicion) -> set:
    """Cd8 como lo aplica la base: autores y, si la hubo, quien devolvió la medición."""
    impedidos = _autores(medicion)
    if medicion.devuelta_por_id is not None:
        impedidos.add(medicion.devuelta_por_id)
    return impedidos


def _aprobadores(medicion_id) -> set:
    return set(Aprobacion.objects.filter(medicion_id=medicion_id).values_list("aprobador_id", flat=True))


def _hay_certificado_vigente(medicion: Medicion) -> bool:
    # Lectura sin bloqueo: con R2 la RLS de UPDATE ocultaría la fila al FOR UPDATE. La barrera ante
    # una carrera es el índice único parcial certificado_vigente_unico.
    return Certificado.objects.filter(
        parcela_id=medicion.parcela_id, periodo_id=medicion.periodo_id, estado=VIGENTE
    ).exists()


def _anulado_sin_vigente(medicion_id) -> bool:
    certificados = Certificado.objects.filter(medicion_id=medicion_id)
    return certificados.filter(estado=ANULADO).exists() and not certificados.filter(estado=VIGENTE).exists()


def _texto_suficiente(texto) -> str | None:
    limpio = (texto or "").strip()
    return limpio if len(limpio) >= LARGO_MINIMO_TEXTO else None


def _crear_version(medicion_id, numero, creada_por_id, co2e, fecha, notas, enmienda_id=None) -> MedicionVersion:
    version = MedicionVersion.objects.create(
        medicion_id=medicion_id,
        numero=numero,
        co2e_toneladas=co2e,
        fecha_muestreo=fecha,
        notas=notas,
        creada_por_id=creada_por_id,
        huella=HUELLA_PROVISIONAL,
        enmienda_id=enmienda_id,
    )
    return MedicionVersion.objects.get(pk=version.pk)


def _estado(medicion_id) -> EstadoMedicion:
    estado, ciclo = Medicion.objects.filter(pk=medicion_id).values_list("estado", "ciclo").get()
    return EstadoMedicion(medicion_id, estado, ciclo)


def _exigir_revision(medicion: Medicion, estado_periodo: str, huella_revisada, estados) -> MedicionVersion:
    """Cd7: período cerrado, estado esperado y la huella revisada igual a la de la versión vigente.

    La huella presentada no tiene columna propia; después de presentar, la base solo admite versiones
    nuevas por enmienda autorizada, que deja la medición otra vez presentada. Por eso la versión
    vigente es la presentada, y el verificador confirma con huella_revisada qué contenido revisó.
    """
    if estado_periodo != CERRADO:
        raise ReglaIncumplida("Cd7", "la verificación ocurre con el período cerrado")
    if medicion.estado not in estados:
        raise ReglaIncumplida("Cd7", "la medición no está presentada para verificación")
    vigente = _version_vigente(medicion.pk)
    if vigente is None or vigente.huella != str(huella_revisada):
        raise ReglaIncumplida("Cd7", "la huella revisada no es la de la versión vigente")
    return vigente


# --------------------------------------------------------------------------- O1: técnico


@_servicio
def registrar_medicion(actor, parcela_id, periodo_id, *, co2e_toneladas: Decimal, fecha_muestreo: date,
                       notas: str | None = None) -> MedicionResultado:
    estado_periodo, _ = _periodo_compartido(periodo_id)
    if estado_periodo != ABIERTO:
        raise ReglaIncumplida("Cd5", "el período no está abierto")
    medicion = Medicion.objects.create(parcela_id=parcela_id, periodo_id=periodo_id, registrada_por=actor)
    version = _crear_version(medicion.pk, 1, actor.pk, co2e_toneladas, fecha_muestreo, notas)
    return MedicionResultado(medicion.pk, BORRADOR, 1, version.numero, version.huella)


def _medicion_propia_en_borrador(actor, medicion_id) -> Medicion:
    """Cd6 (propia), Cd5 (período abierto) y Cd6 (borrador), en ese orden."""
    visible = _medicion_visible(medicion_id)
    if visible.registrada_por_id != actor.pk:
        raise ReglaIncumplida("Cd6", "solo quien registró la medición puede cambiarla")
    estado_periodo, _ = _periodo_compartido(visible.periodo_id)
    if estado_periodo != ABIERTO:
        raise ReglaIncumplida("Cd5", "el período no está abierto")
    medicion = _medicion_bloqueada(medicion_id)
    if medicion.estado != BORRADOR:
        raise ReglaIncumplida("Cd6", "la medición ya no está en borrador")
    return medicion


@_servicio
def modificar_medicion(actor, medicion_id, *, co2e_toneladas: Decimal, fecha_muestreo: date,
                       notas: str | None = None) -> MedicionResultado:
    """Agrega una versión; las anteriores no se tocan (H3)."""
    medicion = _medicion_propia_en_borrador(actor, medicion_id)
    ultima = _version_vigente(medicion.pk)
    numero = (ultima.numero if ultima else 0) + 1
    version = _crear_version(medicion.pk, numero, actor.pk, co2e_toneladas, fecha_muestreo, notas)
    return MedicionResultado(medicion.pk, medicion.estado, medicion.ciclo, version.numero, version.huella)


@_servicio
def presentar_medicion(actor, medicion_id) -> MedicionResultado:
    """Devuelve la huella presentada: la de la versión vigente, que el verificador debe revisar."""
    medicion = _medicion_propia_en_borrador(actor, medicion_id)
    vigente = _version_vigente(medicion.pk)
    if vigente is None:
        raise ReglaIncumplida("Cd6", "la medición no tiene versiones")
    Medicion.objects.filter(pk=medicion.pk).update(estado=PRESENTADA)
    return MedicionResultado(medicion.pk, PRESENTADA, medicion.ciclo, vigente.numero, vigente.huella)


# --------------------------------------------------------------------------- O1: verificación


def _emitir(medicion: Medicion, version: MedicionVersion, aprobadores) -> uuid.UUID:
    """Firma con la hora de la base justo antes del INSERT; el disparador valida el payload."""
    certificado_id = uuid.uuid4()
    payload = firma.construir_payload(
        certificado_id, medicion.parcela_id, medicion.periodo_id, medicion.pk, version.numero,
        version.co2e_toneladas, version.huella, aprobadores, _hora_de_la_base(),
    )
    documento = firma.firmar(payload)
    Certificado.objects.create(
        id=certificado_id,
        parcela_id=medicion.parcela_id,
        periodo_id=medicion.periodo_id,
        medicion_id=medicion.pk,
        version_id=version.pk,
        ciclo=medicion.ciclo,
        estado=VIGENTE,
        payload=documento["payload"],
        firma=documento["signature"],
        clave_publica=documento["public_key"],
        alg=documento["alg"],
        key_id=documento["payload"]["key_id"],
    )
    return certificado_id


@_servicio
def aprobar_medicion(actor, medicion_id, *, huella_revisada: str) -> AprobacionResultado:
    """Registra la aprobación del ciclo y, si completa las requeridas, emite el certificado.

    Hasta Valto basta una aprobación; por encima hacen falta dos verificadores distintos. La emisión
    ocurre en esta misma transacción: si la firma o el INSERT fallan, tampoco queda la aprobación.
    """
    visible = _medicion_visible(medicion_id)
    estado_periodo, _ = _periodo_compartido(visible.periodo_id)
    medicion = _medicion_bloqueada(medicion_id)
    if _hay_certificado_vigente(medicion):
        raise ReglaIncumplida("Cd10", "ya existe un certificado vigente para la parcela y el período")
    vigente = _exigir_revision(medicion, estado_periodo, huella_revisada, (PRESENTADA, APROBADA))
    alto = vigente.co2e_toneladas > plazos.leer_parametro(plazos.CLAVE_VALTO)
    if medicion.estado == APROBADA and not alto:
        raise ReglaIncumplida("Cd7", "la medición no está presentada para verificación")
    if actor.pk in _impedidos_para_aprobar(medicion):
        raise ReglaIncumplida("Cd8", "quien registró, modificó, presentó o devolvió la medición no la aprueba")
    if Aprobacion.objects.filter(medicion_id=medicion.pk, ciclo=medicion.ciclo, aprobador_id=actor.pk).exists():
        raise ReglaIncumplida("Cd8", "el actor ya aprobó la medición en este ciclo")
    Aprobacion.objects.create(
        medicion_id=medicion.pk, version_id=vigente.pk, ciclo=medicion.ciclo, aprobador=actor,
        huella_aprobada=vigente.huella,
    )
    aprobadores = set(
        Aprobacion.objects.filter(
            medicion_id=medicion.pk, ciclo=medicion.ciclo, version_id=vigente.pk, huella_aprobada=vigente.huella
        ).values_list("aprobador_id", flat=True)
    )
    requeridas = 2 if alto else 1
    certificado_id = _emitir(medicion, vigente, aprobadores) if len(aprobadores) >= requeridas else None
    final = _estado(medicion.pk)
    return AprobacionResultado(medicion.pk, final.estado, final.ciclo, len(aprobadores), requeridas, certificado_id)


@_servicio
def devolver_medicion(actor, medicion_id, *, huella_revisada: str) -> EstadoMedicion:
    visible = _medicion_visible(medicion_id)
    estado_periodo, _ = _periodo_compartido(visible.periodo_id)
    medicion = _medicion_bloqueada(medicion_id)
    _exigir_revision(medicion, estado_periodo, huella_revisada, (PRESENTADA,))
    if actor.pk in _autores(medicion):
        raise ReglaIncumplida("Cd8", "quien registró, modificó o presentó la medición no la devuelve")
    Medicion.objects.filter(pk=medicion.pk).update(estado=DEVUELTA, devuelta_por_id=actor.pk)
    return _estado(medicion.pk)


@_servicio
def reasignar_verificacion(actor, medicion_id, destino_id) -> ReasignacionResultado:
    """Cambia el verificador asignado. La ejecuta un R7 (lo exige la base).

    Procede si no hay verificador asignado, si el asignado no puede aprobar por Cd8 o si vencieron
    los días hábiles del plazo de verificación desde el cierre (Cd19).
    """
    visible = _medicion_visible(medicion_id)
    estado_periodo, cerrado_en = _periodo_compartido(visible.periodo_id)
    medicion = _medicion_bloqueada(medicion_id)
    if estado_periodo != CERRADO or medicion.estado != PRESENTADA:
        raise ReglaIncumplida("Cd19", "solo se reasigna una medición presentada con el período cerrado")
    if not RolUsuario.objects.filter(usuario_id=destino_id, rol_id=ROL_VERIFICADOR, hasta__isnull=True).exists():
        raise ReglaIncumplida("Cd19", "el destino no tiene el rol de verificador vigente")
    impedidos = _impedidos_para_aprobar(medicion)
    if destino_id in impedidos:
        raise ReglaIncumplida("Cd8", "el destino registró, modificó o devolvió la medición")
    actual = medicion.verificador_asignado_id
    if actual is None:
        causa = CAUSA_SIN_ASIGNAR
    elif actual in impedidos:
        causa = CAUSA_CD8
    elif plazos.plazo_habil_vencido(
        cerrado_en, _ahora(), plazos.leer_parametro_entero(plazos.CLAVE_PLAZO_VERIFICACION)
    ):
        causa = CAUSA_PLAZO
    else:
        raise ReglaIncumplida("Cd19", "el verificador asignado puede aprobar y el plazo de verificación sigue vigente")
    Medicion.objects.filter(pk=medicion.pk).update(verificador_asignado_id=destino_id)
    return ReasignacionResultado(medicion.pk, causa)


# --------------------------------------------------------------------------- O2: períodos


def _resultado_periodo(periodo_id) -> PeriodoResultado:
    estado, cerrado_en = Periodo.objects.filter(pk=periodo_id).values_list("estado", "cerrado_en").get()
    por_estado = dict(
        Medicion.objects.filter(periodo_id=periodo_id).values("estado").annotate(n=Count("id")).values_list("estado", "n")
    )
    return PeriodoResultado(periodo_id, estado, cerrado_en, por_estado.get(SIN_PRESENTAR, 0), por_estado.get(PRESENTADA, 0))


@_servicio
def abrir_periodo(actor, inicio: date, fin: date) -> PeriodoResultado:
    """La base exige el rol R7 y que el período nazca abierto, sin fecha ni autor de cierre."""
    if fin <= inicio:
        raise ValueError("El fin del período debe ser posterior al inicio.")
    periodo = Periodo.objects.create(inicio=inicio, fin=fin, estado=ABIERTO)
    return PeriodoResultado(periodo.pk, ABIERTO, None, 0, 0)


@_servicio
def cerrar_periodo(actor, periodo_id) -> PeriodoResultado:
    """Cierre irreversible. La base fija fecha y autor y pasa los borradores a sin_presentar."""
    periodo = Periodo.objects.select_for_update().filter(pk=periodo_id).first()
    if periodo is None:
        raise NoEncontrado("El período no existe.")
    if periodo.estado != ABIERTO:
        raise ReglaIncumplida("Cd5", "el período ya está cerrado")
    Periodo.objects.filter(pk=periodo_id).update(estado=CERRADO, cerrado_en=Now(), cerrado_por_id=actor.pk)
    return _resultado_periodo(periodo_id)


# --------------------------------------------------------------------------- O3: certificados


def _registrar_aviso_gerencia(certificado: Certificado, actor) -> None:
    """Aviso prioritario a la gerencia. Corre en la transacción de la anulación: si falla, no se anula."""
    Alerta.objects.create(
        tipo=TIPO_AVISO_ANULACION,
        prioridad=Alerta.Prioridad.PRIORITARIA,
        usuario_id=actor.pk,
        parcela_id=certificado.parcela_id,
        medicion_id=certificado.medicion_id,
        detalle={"certificado_id": str(certificado.pk), "ciclo": certificado.ciclo},
    )


@_servicio
def anular_certificado(actor, certificado_id, *, justificacion: str) -> AnulacionResultado:
    """Anula un certificado vigente (Cd20). La base libera (parcela, período) y devuelve la medición a
    presentada con un ciclo nuevo. No reemite: otro certificado solo surge de una aprobación completa.
    """
    texto = _texto_suficiente(justificacion)
    if texto is None:
        raise ReglaIncumplida("Cd20", f"la justificación es obligatoria ({LARGO_MINIMO_TEXTO} caracteres como mínimo)")
    visible = Certificado.objects.filter(pk=certificado_id).values_list("medicion_id", "periodo_id").first()
    if visible is None:
        raise NoEncontrado("El certificado no existe o no es visible para el actor.")
    medicion_id, periodo_id = visible
    _periodo_compartido(periodo_id)
    _medicion_bloqueada(medicion_id)
    certificado = Certificado.objects.select_for_update().filter(pk=certificado_id).first()
    if certificado is None:
        raise NoEncontrado("El certificado no existe o el actor no puede anularlo.")
    if certificado.estado != VIGENTE:
        raise ReglaIncumplida("Cd20", "solo se anula un certificado vigente")
    if Aprobacion.objects.filter(
        medicion_id=medicion_id, version_id=certificado.version_id, aprobador_id=actor.pk
    ).exists():
        raise ReglaIncumplida("Cd20", "quien aprobó la versión certificada no anula su certificado")
    Certificado.objects.filter(pk=certificado_id).update(
        estado=ANULADO, anulado_en=Now(), anulado_por_id=actor.pk, justificacion_anulacion=texto
    )
    _registrar_aviso_gerencia(certificado, actor)
    final = _estado(medicion_id)
    return AnulacionResultado(certificado_id, ANULADO, medicion_id, final.estado, final.ciclo)


def _etapa(etapa: str, rol: str, momento: datetime | None, resultado: str, actor_id) -> dict:
    return {
        "etapa": etapa,
        "rol": rol,
        "fecha": firma.formatear_fecha(momento) if momento else None,
        "resultado": resultado,
        "actor": firma.seudonimo(actor_id) if actor_id else None,
    }


@_servicio
def exportar_certificado(actor, certificado_id) -> ExportacionResultado:
    """Documento firmado tal como se emitió, más la trazabilidad, en JSON canónico, y su SHA-256.

    Los actores aparecen solo como seudónimo (16 hex). El rol de cada etapa es el que exige la
    operación. La presentación no guarda fecha propia (fecha nula) y la emisión no guarda su actor:
    se toma el aprobador cuya aprobación ocurrió en la misma transacción que la emisión.
    """
    certificado = Certificado.objects.filter(pk=certificado_id).first()
    if certificado is None:
        raise NoEncontrado("El certificado no existe o no es visible para el actor.")
    medicion = _medicion_visible(certificado.medicion_id)
    aprobaciones = list(
        Aprobacion.objects.filter(
            medicion_id=medicion.pk, ciclo=certificado.ciclo, version_id=certificado.version_id
        ).order_by("aprobada_en", "aprobador_id")
    )
    emisor = next((a.aprobador_id for a in aprobaciones if a.aprobada_en == certificado.emitido_en), None)
    etapas = [
        _etapa("registro", "R1", medicion.creada_en, "registrada", medicion.registrada_por_id),
        _etapa("presentacion", "R1", None, "presentada", medicion.registrada_por_id),
        *[_etapa("aprobacion", "R2", a.aprobada_en, "aprobada", a.aprobador_id) for a in aprobaciones],
        _etapa("emision", "R2", certificado.emitido_en, "emitido", emisor),
    ]
    if certificado.estado == ANULADO:
        etapas.append(_etapa("anulacion", "R7", certificado.anulado_en, "anulado", certificado.anulado_por_id))
    contenido = firma.canonico({
        "certificado": {
            "payload": certificado.payload,
            "signature": certificado.firma,
            "public_key": certificado.clave_publica,
            "alg": certificado.alg,
        },
        "estado": certificado.estado,
        "trazabilidad": etapas,
    })
    return ExportacionResultado(certificado.pk, contenido, hashlib.sha256(contenido).hexdigest())


# --------------------------------------------------------------------------- O4: enmiendas


@_servicio
def solicitar_enmienda(actor, medicion_id, *, motivo: str, co2e_nuevo: Decimal, fecha_nueva: date,
                       notas_nuevas: str | None = None) -> EnmiendaResultado:
    """Cd11: período cerrado; plazo desde el cierre o certificado anulado sin otro vigente; el
    solicitante registró la medición o la revisó (la aprobó o la devolvió). Guarda como valor
    anterior la versión vigente y como posterior los valores pedidos.
    """
    visible = _medicion_visible(medicion_id)
    vinculados = {visible.registrada_por_id, visible.devuelta_por_id} | _aprobadores(visible.pk)
    if actor.pk not in vinculados:
        raise ReglaIncumplida("Cd11", "el solicitante no registró ni revisó la medición")
    texto = _texto_suficiente(motivo)
    if texto is None:
        raise ReglaIncumplida("Cd11", f"la justificación es obligatoria ({LARGO_MINIMO_TEXTO} caracteres como mínimo)")
    estado_periodo, cerrado_en = _periodo_compartido(visible.periodo_id)
    medicion = _medicion_bloqueada(medicion_id)
    if estado_periodo != CERRADO:
        raise ReglaIncumplida("Cd11", "solo se enmienda una medición con el período cerrado")
    if not plazos.enmienda_en_plazo(
        cerrado_en, _ahora(), plazos.leer_parametro_entero(plazos.CLAVE_PLAZO_ENMIENDA),
        _anulado_sin_vigente(medicion.pk),
    ):
        raise ReglaIncumplida("Cd11", "venció el plazo de enmienda y no hay un certificado anulado sin otro vigente")
    if Enmienda.objects.filter(medicion_id=medicion.pk, estado=SOLICITADA).exists():
        raise ReglaIncumplida("Cd11", "la medición ya tiene una enmienda solicitada")
    base = _version_vigente(medicion.pk)
    enmienda = Enmienda.objects.create(
        medicion_id=medicion.pk,
        version_base=base,
        solicitante=actor,
        motivo=texto,
        co2e_nuevo=co2e_nuevo,
        fecha_nueva=fecha_nueva,
        notas_nuevas=notas_nuevas,
    )
    return EnmiendaResultado(enmienda.pk, SOLICITADA, medicion.pk, medicion.estado, medicion.ciclo, None)


@_servicio
def resolver_enmienda(actor, enmienda_id, *, autorizar: bool) -> EnmiendaResultado:
    """Cd12: autorizador independiente; al autorizar, plazo contado hasta la SOLICITUD y valores
    anterior y posterior presentes.

    Autorizar crea la versión nueva a nombre del solicitante y deja la medición presentada para una
    verificación completa de esa versión. El ciclo no cambia: la base solo lo sube al anular un
    certificado. Con un certificado vigente la medición sigue certificada y toda aprobación queda
    bloqueada por Cd10 hasta que un R7 lo anule. Rechazar no cambia la medición.
    """
    visible = Enmienda.objects.filter(pk=enmienda_id).values_list("medicion_id", flat=True).first()
    if visible is None:
        raise NoEncontrado("La enmienda no existe o no es visible para el actor.")
    medicion_visible = _medicion_visible(visible)
    estado_periodo, cerrado_en = _periodo_compartido(medicion_visible.periodo_id)
    medicion = _medicion_bloqueada(visible)
    enmienda = Enmienda.objects.select_for_update().filter(pk=enmienda_id).first()
    if enmienda is None:
        raise NoEncontrado("La enmienda no existe o el actor no puede resolverla.")
    if enmienda.estado != SOLICITADA:
        raise ReglaIncumplida("Cd12", "la enmienda ya fue resuelta")
    if actor.pk in {enmienda.solicitante_id, medicion.registrada_por_id} | _aprobadores(medicion.pk):
        raise ReglaIncumplida("Cd12", "el autorizador debe ser distinto del solicitante, del registrante y de todo aprobador")
    if not autorizar:
        Enmienda.objects.filter(pk=enmienda.pk).update(estado=RECHAZADA, autorizador_id=actor.pk, resuelta_en=Now())
        return EnmiendaResultado(enmienda.pk, RECHAZADA, medicion.pk, medicion.estado, medicion.ciclo, None)
    if _texto_suficiente(enmienda.motivo) is None or enmienda.version_base_id is None:
        raise ReglaIncumplida("Cd12", "faltan la justificación o los valores anterior y posterior")
    if estado_periodo != CERRADO or not plazos.enmienda_en_plazo(
        cerrado_en, enmienda.solicitada_en, plazos.leer_parametro_entero(plazos.CLAVE_PLAZO_ENMIENDA),
        _anulado_sin_vigente(medicion.pk),
    ):
        raise ReglaIncumplida("Cd12", "la solicitud se hizo fuera del plazo de enmienda")
    Enmienda.objects.filter(pk=enmienda.pk).update(estado=AUTORIZADA, autorizador_id=actor.pk, resuelta_en=Now())
    ultima = _version_vigente(medicion.pk)
    version = _crear_version(
        medicion.pk, ultima.numero + 1, enmienda.solicitante_id, enmienda.co2e_nuevo, enmienda.fecha_nueva,
        enmienda.notas_nuevas, enmienda_id=enmienda.pk,
    )
    if medicion.estado in (DEVUELTA, SIN_PRESENTAR, APROBADA):
        Medicion.objects.filter(pk=medicion.pk).update(estado=PRESENTADA)
    final = _estado(medicion.pk)
    return EnmiendaResultado(enmienda.pk, AUTORIZADA, medicion.pk, final.estado, final.ciclo, version.numero)
