"""Servicios del catálogo de fincas (O5): fincas, parcelas, propietarios y asignación de técnicos.

Mismo patrón que mediciones.servicios: el actor es el primer argumento, cada servicio corre en una
transacción con el actor declarado y una violación lanza ReglaIncumplida sin dejar cambios. Los
servicios hacen cumplir Cd14 (separación respecto del dato: el actor no es propietario ni se asigna a
sí mismo; la cuenta destino tiene el rol que exige la operación), Cd15 (sin mediciones en curso ni
certificados vigentes donde corresponde) y las invariantes estructurales: UNIDAD (sin traslapes),
GEOMETRIA, CODIGO, PROPIEDAD y VIGENCIA. El rol del actor lo decide la autorización.

La propiedad se define por finca (catalogo_propiedad) y la heredan sus parcelas. Las bajas son
lógicas: no existe un servicio de borrado físico y app_rw no tiene DELETE.

Cada alta o cambio que afecta a una cuenta registra un aviso para R7 con mediciones.alertas: uno por
cuenta afectada, en la misma transacción (si el aviso falla, la operación no ocurre).

Las fechas (alta, inicio y fin de propiedad, inicio de asignación, baja) son now() de la base, la
misma hora de la transacción que usan las funciones de RLS; Now() de Django en PostgreSQL es
statement_timestamp() y dejaría, por ejemplo, una asignación todavía no vigente dentro de su
propia transacción.

Bloqueos, siempre en este orden: finca, parcelas (por id). Bloquear la parcela FOR UPDATE impide
también que se registren mediciones sobre ella mientras dura la comprobación de Cd15.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from django.db import connection

from catalogo import geometria
from catalogo.models import Asignacion, Finca, Parcela, Propiedad
from mediciones import alertas, transaccion
from mediciones.errores import NoEncontrado, ReglaIncumplida
from mediciones.models import Medicion
from usuarios.models import RolUsuario

ROL_TECNICO = "R1"
ROL_PROPIETARIO = "R6"
# En curso: todavía puede cambiar de estado por el flujo normal de verificación.
ESTADOS_EN_CURSO = (
    Medicion.Estado.BORRADOR,
    Medicion.Estado.PRESENTADA,
    Medicion.Estado.DEVUELTA,
    Medicion.Estado.APROBADA,
)
# La base mantiene "certificada" si y solo si la medición tiene un certificado vigente.
ESTADO_CON_CERTIFICADO_VIGENTE = Medicion.Estado.CERTIFICADA
# Propósito que habilita la política medicion_estado_para_catalogo (migración mediciones 0010).
PROPOSITO_CATALOGO = "catalogo"

_RESTRICCIONES = {
    "parcela_codigo_unico_por_finca": ("CODIGO", "ya existe una parcela con ese código en la finca"),
    "parcela_geom_valida": ("GEOMETRIA", "el polígono de la parcela no es válido"),
    "parcela_geom_srid": ("GEOMETRIA", "el polígono debe estar en CRTM05 (SRID 5367)"),
    "propiedad_vigente_unica": ("PROPIEDAD", "la persona ya es propietaria vigente de la finca"),
    "asignacion_hasta_posterior": ("Cd14", "la asignación debe vencer después de su inicio"),
}


# --------------------------------------------------------------------------- resultados


@dataclass(frozen=True)
class FincaResultado:
    finca_id: uuid.UUID
    propietarios: int
    avisos: int


@dataclass(frozen=True)
class ParcelaResultado:
    parcela_id: uuid.UUID
    finca_id: uuid.UUID
    codigo: str
    dada_de_baja_en: datetime | None
    avisos: int


@dataclass(frozen=True)
class PropietariosResultado:
    finca_id: uuid.UUID
    propietarios: int
    agregados: int
    retirados: int
    avisos: int


@dataclass(frozen=True)
class AsignacionResultado:
    asignacion_id: uuid.UUID
    parcela_id: uuid.UUID
    vence_en: datetime
    prioridad: str


# --------------------------------------------------------------------------- infraestructura


def _regla_de_la_base(error) -> ReglaIncumplida | None:
    sqlstate, diag = transaccion.diagnostico(error)
    if diag is None:
        return None
    mensaje = diag.message_primary or ""
    if sqlstate in ("23505", "23514") and diag.constraint_name in _RESTRICCIONES:
        return ReglaIncumplida(*_RESTRICCIONES[diag.constraint_name])
    if sqlstate == "23000" and mensaje.startswith("Traslape de parcelas"):
        return ReglaIncumplida("UNIDAD", "la parcela se traslapa con otra parcela activa")
    if sqlstate == "23000" and mensaje.startswith("Asignación rechazada"):
        return ReglaIncumplida("Cd14", "la cuenta destino no tiene el rol R1 vigente")
    # PostGIS informa un WKT mal formado como error interno con el texto del parser.
    if sqlstate == "XX000" and "geometry" in mensaje.lower():
        return ReglaIncumplida("GEOMETRIA", "el polígono de la parcela no es válido")
    return None


_servicio = transaccion.servicio(_regla_de_la_base)


def _uuid(valor) -> uuid.UUID:
    return valor if isinstance(valor, uuid.UUID) else uuid.UUID(str(valor))


def _ids(valores) -> list[uuid.UUID]:
    """Identificadores normalizados y sin repetir, en el orden recibido."""
    return list(dict.fromkeys(_uuid(v) for v in valores or ()))


def _con_rol_vigente(usuario_ids, rol: str) -> set:
    return set(
        RolUsuario.objects.filter(usuario_id__in=list(usuario_ids), rol_id=rol, hasta__isnull=True)
        .values_list("usuario_id", flat=True)
    )


def _propietarios_vigentes(finca_id) -> set:
    return set(Propiedad.objects.filter(finca_id=finca_id, hasta__isnull=True).values_list("dueno_id", flat=True))


def _finca_bloqueada(finca_id) -> Finca:
    finca = Finca.objects.select_for_update().filter(pk=finca_id).first()
    if finca is None:
        raise NoEncontrado("La finca no existe.")
    if finca.dada_de_baja_en is not None:
        raise ReglaIncumplida("VIGENCIA", "la finca está dada de baja")
    return finca


def _parcela_bloqueada(parcela_id) -> Parcela:
    parcela = Parcela.objects.select_for_update().filter(pk=parcela_id).first()
    if parcela is None:
        raise NoEncontrado("La parcela no existe.")
    if parcela.dada_de_baja_en is not None:
        raise ReglaIncumplida("VIGENCIA", "la parcela está dada de baja")
    return parcela


def _proposito(valor: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('app.proposito', %s, true)", [valor])


def _situacion_de_mediciones(parcela_ids) -> tuple[bool, bool]:
    """(hay mediciones en curso, hay certificado vigente) en esas parcelas.

    El propósito se declara solo durante la consulta; fuera de ella la RLS vuelve a ocultar las filas
    a quien no tiene rol de lectura de mediciones.
    """
    _proposito(PROPOSITO_CATALOGO)
    try:
        estados = set(
            Medicion.objects.filter(
                parcela_id__in=list(parcela_ids),
                estado__in=[*ESTADOS_EN_CURSO, ESTADO_CON_CERTIFICADO_VIGENTE],
            ).values_list("estado", flat=True)
        )
    finally:
        _proposito("")
    return bool(estados & set(ESTADOS_EN_CURSO)), ESTADO_CON_CERTIFICADO_VIGENTE in estados


def _resultado_parcela(parcela_id, avisos: int = 0) -> ParcelaResultado:
    finca_id, codigo, baja = (
        Parcela.objects.filter(pk=parcela_id).values_list("finca_id", "codigo", "dada_de_baja_en").get()
    )
    return ParcelaResultado(parcela_id, finca_id, codigo, baja, avisos)


# --------------------------------------------------------------------------- fincas y parcelas


@_servicio
def crear_finca(actor, nombre: str, propietarios) -> FincaResultado:
    """Finca con uno o varios propietarios, todos con R6 vigente y distintos del actor (Cd14)."""
    nombre = (nombre or "").strip()
    if not nombre:
        raise ValueError("La finca necesita un nombre.")
    ids = _ids(propietarios)
    if not ids:
        raise ReglaIncumplida("PROPIEDAD", "la finca necesita al menos un propietario")
    if actor.pk in ids:
        raise ReglaIncumplida("Cd14", "quien da de alta la finca no puede figurar como propietario")
    if set(ids) - _con_rol_vigente(ids, ROL_PROPIETARIO):
        raise ReglaIncumplida("Cd14", "todo propietario debe tener el rol R6 vigente")
    ahora = transaccion.hora_de_la_base()
    finca = Finca.objects.create(nombre=nombre, creada_en=ahora)
    for dueno_id in ids:
        Propiedad.objects.create(dueno_id=dueno_id, finca_id=finca.pk, desde=ahora)
    for dueno_id in ids:
        alertas.registrar_aviso(
            alertas.TIPO_ALTA_FINCA, actor.pk, cuenta_afectada_id=dueno_id, detalle={"finca_id": str(finca.pk)}
        )
    return FincaResultado(finca.pk, len(ids), len(ids))


@_servicio
def crear_parcela(actor, finca_id, codigo: str, wkt: str) -> ParcelaResultado:
    """Parcela de una finca activa. Cd14: el actor no es propietario de la finca (la propiedad se
    hereda). La base rechaza los traslapes (UNIDAD) y los polígonos inválidos (GEOMETRIA).
    """
    codigo = (codigo or "").strip()
    if not codigo:
        raise ValueError("La parcela necesita un código.")
    finca = _finca_bloqueada(finca_id)
    propietarios = _propietarios_vigentes(finca.pk)
    if actor.pk in propietarios:
        raise ReglaIncumplida("Cd14", "un propietario de la finca no da de alta sus parcelas")
    parcela_id = geometria.crear_parcela(finca.pk, codigo, wkt)
    for dueno_id in sorted(propietarios):
        alertas.registrar_aviso(
            alertas.TIPO_ALTA_PARCELA, actor.pk, cuenta_afectada_id=dueno_id, parcela_id=parcela_id,
            detalle={"finca_id": str(finca.pk)},
        )
    return _resultado_parcela(parcela_id, len(propietarios))


@_servicio
def cambiar_propietarios(actor, finca_id, *, agregar=(), retirar=()) -> PropietariosResultado:
    """Agrega o retira propietarios de una finca; las fechas las fija now() de la base.

    Cd14: nadie se agrega a sí mismo y todo agregado tiene R6 vigente. Cd15: ninguna parcela de la
    finca tiene mediciones en curso. Los certificados vigentes no lo impiden y no cambian: el
    documento firmado no registra titular, y el de cada fecha queda en el historial de propiedad.
    """
    agregar, retirar = _ids(agregar), _ids(retirar)
    if not agregar and not retirar:
        raise ValueError("No hay propietarios que agregar ni retirar.")
    if set(agregar) & set(retirar):
        raise ValueError("Una misma persona no se agrega y se retira a la vez.")
    finca = _finca_bloqueada(finca_id)
    parcelas = list(Parcela.objects.select_for_update().filter(finca_id=finca.pk).order_by("id").values_list("id", flat=True))
    if actor.pk in agregar:
        raise ReglaIncumplida("Cd14", "nadie se agrega a sí mismo como propietario")
    if set(agregar) - _con_rol_vigente(agregar, ROL_PROPIETARIO):
        raise ReglaIncumplida("Cd14", "todo propietario agregado debe tener el rol R6 vigente")
    vigentes = _propietarios_vigentes(finca.pk)
    if set(agregar) & vigentes:
        raise ReglaIncumplida("PROPIEDAD", "la persona ya es propietaria vigente de la finca")
    if set(retirar) - vigentes:
        raise ReglaIncumplida("PROPIEDAD", "solo se retira a un propietario vigente")
    if not (vigentes - set(retirar)) | set(agregar):
        raise ReglaIncumplida("PROPIEDAD", "la finca debe conservar al menos un propietario")
    en_curso, _ = _situacion_de_mediciones(parcelas)
    if en_curso:
        raise ReglaIncumplida("Cd15", "hay mediciones en curso en parcelas de la finca")
    ahora = transaccion.hora_de_la_base()
    if retirar:
        Propiedad.objects.filter(finca_id=finca.pk, dueno_id__in=retirar, hasta__isnull=True).update(hasta=ahora)
    for dueno_id in agregar:
        Propiedad.objects.create(dueno_id=dueno_id, finca_id=finca.pk, desde=ahora)
    cambios = [(d, "alta") for d in agregar] + [(d, "retiro") for d in retirar]
    for dueno_id, cambio in cambios:
        alertas.registrar_aviso(
            alertas.TIPO_CAMBIO_PROPIETARIOS, actor.pk, cuenta_afectada_id=dueno_id,
            detalle={"finca_id": str(finca.pk), "cambio": cambio},
        )
    total = len(_propietarios_vigentes(finca.pk))
    return PropietariosResultado(finca.pk, total, len(agregar), len(retirar), len(cambios))


@_servicio
def modificar_parcela(actor, parcela_id, *, codigo: str | None = None, wkt: str | None = None) -> ParcelaResultado:
    """Cambia el código o los límites. Cd14: el actor no es propietario de la finca (la propiedad se
    hereda, igual que al crear la parcela). Cd15: sin mediciones en curso y, si cambian los límites,
    sin certificado vigente. Los traslapes se rechazan igual que al crear (UNIDAD).
    """
    if codigo is None and wkt is None:
        raise ValueError("No hay cambios que aplicar a la parcela.")
    if codigo is not None and not codigo.strip():
        raise ValueError("La parcela necesita un código.")
    parcela = _parcela_bloqueada(parcela_id)
    if actor.pk in _propietarios_vigentes(parcela.finca_id):
        raise ReglaIncumplida("Cd14", "un propietario de la finca no modifica sus parcelas")
    en_curso, certificada = _situacion_de_mediciones([parcela.pk])
    if en_curso:
        raise ReglaIncumplida("Cd15", "la parcela tiene mediciones en curso")
    if wkt is not None and geometria.limites_distintos(parcela.pk, wkt):
        if certificada:
            raise ReglaIncumplida("Cd15", "la parcela tiene un certificado vigente: sus límites no cambian")
        geometria.actualizar_limites(parcela.pk, wkt)
    if codigo is not None:
        Parcela.objects.filter(pk=parcela.pk).update(codigo=codigo.strip())
    return _resultado_parcela(parcela.pk)


@_servicio
def asignar_tecnico(actor, parcela_id, tecnico_id, vence_en: datetime) -> AsignacionResultado:
    """Asigna un técnico con vencimiento. Una cobertura temporal es otra asignación con vencimiento.

    Cd14: la cuenta destino es otra persona, tiene R1 vigente y el vencimiento es futuro.
    """
    tecnico_id = _uuid(tecnico_id)
    if tecnico_id == actor.pk:
        raise ReglaIncumplida("Cd14", "nadie se asigna a sí mismo una parcela")
    parcela = _parcela_bloqueada(parcela_id)
    if not _con_rol_vigente([tecnico_id], ROL_TECNICO):
        raise ReglaIncumplida("Cd14", "la cuenta destino no tiene el rol R1 vigente")
    ahora = transaccion.hora_de_la_base()
    if vence_en <= ahora:
        raise ReglaIncumplida("Cd14", "la asignación debe vencer en el futuro")
    asignacion = Asignacion.objects.create(tecnico_id=tecnico_id, parcela_id=parcela.pk, desde=ahora, hasta=vence_en)
    prioridad = alertas.prioridad_para(actor.pk, tecnico_id)
    alertas.registrar_aviso(
        alertas.TIPO_ASIGNACION_TECNICO, actor.pk, prioridad=prioridad, cuenta_afectada_id=tecnico_id,
        parcela_id=parcela.pk, detalle={"asignacion_id": str(asignacion.pk)},
    )
    return AsignacionResultado(asignacion.pk, parcela.pk, vence_en, prioridad)


@_servicio
def dar_de_baja_parcela(actor, parcela_id) -> ParcelaResultado:
    """Baja lógica (dada_de_baja_en = now()). Cd15: sin mediciones en curso ni certificado vigente.

    En la misma transacción termina las asignaciones de técnicos vigentes (hasta = now()); como Cd15
    exige que no haya mediciones en curso, no queda trabajo abierto. Una asignación que todavía no
    empezó no puede terminar antes de su inicio (CHECK asignacion_hasta_posterior): se conserva, y
    registrar_medicion rechaza igual cualquier medición sobre una parcela dada de baja.
    """
    parcela = _parcela_bloqueada(parcela_id)
    en_curso, certificada = _situacion_de_mediciones([parcela.pk])
    if en_curso:
        raise ReglaIncumplida("Cd15", "la parcela tiene mediciones en curso")
    if certificada:
        raise ReglaIncumplida("Cd15", "la parcela tiene un certificado vigente")
    ahora = transaccion.hora_de_la_base()
    Asignacion.objects.filter(parcela_id=parcela.pk, desde__lt=ahora, hasta__gt=ahora).update(hasta=ahora)
    Parcela.objects.filter(pk=parcela.pk).update(dada_de_baja_en=ahora)
    return _resultado_parcela(parcela.pk)
