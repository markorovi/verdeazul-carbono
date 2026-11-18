"""Servicios de cuentas y roles (O6), ventanas de auditoría, acceso de emergencia y recuperación.

Mismo patrón que los demás servicios: el actor es el primer argumento, cada servicio corre en la
transacción común con el actor declarado y una violación lanza ReglaIncumplida sin dejar cambios.
Hacen cumplir Cd13 (nadie opera sobre sus propios roles o su propia cuenta; sin pares de roles
excluyentes), Cd23 (ventanas de auditoría) y Cd24 (emergencia). El rol del ACTOR lo decide la
autorización; el rol de las cuentas afectadas (auditor R5, autorizadores R4 y R7, rol suplido R1 o
R2) es un dato del objeto y lo comprueba el servicio.

Las exclusiones de roles, la duración máxima de la emergencia y la independencia de autorizadores
ya las impone la base (disparador y restricciones CHECK). El servicio las verifica antes para dar
una condición estable y traduce el rechazo de la base si se le adelanta una operación simultánea.

canjear_codigo, acceso_emergencia_vigente y consumir_emergencia no reciben actor: los usa quien
todavía no tiene sesión o el punto de decisión de acceso.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from django.contrib.auth.password_validation import validate_password
from django.contrib.sessions.models import Session
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import DatabaseError, transaction
from django.db.models import F, Q

from mediciones import alertas, plazos, transaccion
from mediciones.errores import NoEncontrado, ReglaIncumplida
from usuarios import autenticacion, cifrado, codigos, totp, ventanas
from usuarios.models import (
    DURACION_MAXIMA_EMERGENCIA,
    MAX_INTENTOS_CODIGO,
    PERFIL_SOLO_LECTURA,
    ROLES_SUPLIBLES,
    AccesoEmergencia,
    CodigoUnUso,
    ExclusionEstatica,
    Rol,
    RolUsuario,
    Usuario,
    VentanaAuditoria,
)

ALTA = CodigoUnUso.Proposito.ALTA
RECUPERACION = CodigoUnUso.Proposito.RECUPERACION
ROL_AUDITOR = "R5"
ROLES_AUTORIZADORES = ("R4", "R7")
CLAVE_VENTANA_AUDITOR = "waud_dias_anuales"
CLAVE_EMERGENCIA_HORAS = "temg_horas"
CLAVE_REVISION_EMERGENCIA_HORAS = "trev_emg_horas"
TIPO_REVISION_EMERGENCIA = "revision_emergencia"
TIPO_RECUPERACION_EMITIDA = "recuperacion_emitida"
CLAVE_SESION_USUARIO = "_auth_user_id"
# Misma respuesta para toda falla de canje: no revela si la cuenta existe ni qué falló.
FALLO_CANJE = ("RECUPERACION", "no se pudo completar la operación con ese código")

_RESTRICCIONES = {
    "usuarios_usuario_correo_key": ("CUENTA", "ya existe una cuenta con ese correo"),
    "rolusuario_vigente_unico": ("ROL", "la cuenta ya tiene ese rol vigente"),
    "ventana_apertura_independiente": ("Cd23", "quien solicita la ventana no la abre"),
    "emergencia_una_pendiente": ("Cd24", "ya hay una autorización de emergencia pendiente para esa cuenta"),
    "emergencia_beneficiario_distinto_r4": ("Cd24", "el beneficiario no puede ser uno de los autorizadores"),
    "emergencia_beneficiario_distinto_r7": ("Cd24", "el beneficiario no puede ser uno de los autorizadores"),
    "emergencia_autorizadores_distintos": ("Cd24", "las dos autorizaciones deben ser de personas distintas"),
    "emergencia_duracion_maxima": ("Cd24", "la vigencia supera la duración máxima de la emergencia"),
}
_MENSAJES = [
    ("Separación de funciones", ("Cd13", "el rol es incompatible con un rol vigente de la cuenta")),
    ("Ventana: ya fue abierta", ("Cd23", "la solicitud ya fue abierta")),
    ("Emergencia (Cd24)", ("Cd24", "el acceso de emergencia ya fue usado")),
]


# --------------------------------------------------------------------------- resultados


@dataclass(frozen=True)
class AltaResultado:
    usuario_id: uuid.UUID
    vence_en: datetime
    # Se entrega una sola vez y nunca se persiste en claro; repr=False evita que aparezca en registros.
    codigo: str = field(repr=False)


@dataclass(frozen=True)
class CuentaResultado:
    usuario_id: uuid.UUID
    activo: bool
    roles: tuple[str, ...]


@dataclass(frozen=True)
class BajaResultado:
    usuario_id: uuid.UUID
    sesiones_cerradas: int
    codigos_invalidados: int


@dataclass(frozen=True)
class VentanaResultado:
    ventana_id: uuid.UUID
    estado: str


@dataclass(frozen=True)
class EmergenciaResultado:
    acceso_id: uuid.UUID
    estado: str
    vence_en: datetime | None
    revision_vence_en: datetime | None


@dataclass(frozen=True)
class ConsumoResultado:
    rol_suplido: str
    vence_en: datetime


@dataclass(frozen=True)
class CodigoResultado:
    usuario_id: uuid.UUID
    vence_en: datetime
    codigo: str = field(repr=False)


@dataclass(frozen=True)
class CanjeResultado:
    proposito: str
    # Solo en el alta: el secreto TOTP nuevo y su URI, para registrarlo una vez en la aplicación.
    secreto_totp: str | None = field(default=None, repr=False)
    uri_totp: str | None = field(default=None, repr=False)


# --------------------------------------------------------------------------- infraestructura


def _regla_de_la_base(error) -> ReglaIncumplida | None:
    sqlstate, diag = transaccion.diagnostico(error)
    if diag is None:
        return None
    if sqlstate in ("23505", "23514") and diag.constraint_name in _RESTRICCIONES:
        return ReglaIncumplida(*_RESTRICCIONES[diag.constraint_name])
    if sqlstate == "23000":
        mensaje = diag.message_primary or ""
        for prefijo, regla in _MENSAJES:
            if mensaje.startswith(prefijo):
                return ReglaIncumplida(*regla)
    return None


_servicio = transaccion.servicio(_regla_de_la_base)


def _uuid(valor) -> uuid.UUID:
    return valor if isinstance(valor, uuid.UUID) else uuid.UUID(str(valor))


def _roles_vigentes(usuario_id) -> set[str]:
    return set(RolUsuario.objects.filter(usuario_id=usuario_id, hasta__isnull=True).values_list("rol_id", flat=True))


def _cuenta_bloqueada(usuario_id, activa: bool = True) -> Usuario:
    cuenta = Usuario.objects.select_for_update().filter(pk=usuario_id).first()
    if cuenta is None:
        raise NoEncontrado("La cuenta no existe.")
    if activa and not cuenta.activo:
        raise ReglaIncumplida("CUENTA", "la cuenta está dada de baja")
    return cuenta


def _cerrar_sesiones(usuario_id, ahora: datetime) -> int:
    """Borra las sesiones vigentes de la cuenta, incluidas las que esperan el segundo factor."""
    clave = str(usuario_id)
    claves = []
    for sesion in Session.objects.filter(expire_date__gt=ahora).iterator():
        datos = sesion.get_decoded()
        pre = datos.get(autenticacion.CLAVE_PRE_AUTH)
        if datos.get(CLAVE_SESION_USUARIO) == clave or (isinstance(pre, dict) and pre.get("usuario") == clave):
            claves.append(sesion.session_key)
    if claves:
        Session.objects.filter(session_key__in=claves).delete()
    return len(claves)


def _invalidar_codigos(usuario_id, ahora: datetime) -> int:
    """Lleva los códigos pendientes al máximo de intentos: quedan inválidos sin borrarse."""
    return CodigoUnUso.objects.filter(
        usuario_id=usuario_id, usado_en__isnull=True, intentos_fallidos__lt=MAX_INTENTOS_CODIGO, vence_en__gt=ahora
    ).update(intentos_fallidos=MAX_INTENTOS_CODIGO)


def _emitir_codigo(usuario_id, proposito: str, emisor_id, ahora: datetime) -> tuple[str, datetime]:
    """Invalida los códigos pendientes de la cuenta y emite uno nuevo; devuelve el código en claro."""
    _invalidar_codigos(usuario_id, ahora)
    codigo = codigos.generar()
    vence_en = ahora + codigos.vigencia(proposito)
    CodigoUnUso.objects.create(
        usuario_id=usuario_id, proposito=proposito, huella=codigos.huella(codigo), emitido_por_id=emisor_id,
        emitido_en=ahora, vence_en=vence_en,
    )
    return codigo, vence_en


def _resultado_cuenta(usuario_id) -> CuentaResultado:
    activo = Usuario.objects.filter(pk=usuario_id).values_list("activo", flat=True).get()
    return CuentaResultado(usuario_id, activo, tuple(sorted(_roles_vigentes(usuario_id))))


# --------------------------------------------------------------------------- cuentas y roles


@_servicio
def alta_cuenta(actor, correo: str, nombre: str) -> AltaResultado:
    """Cuenta nueva sin contraseña utilizable ni roles, con creado_por = actor y un código de alta."""
    correo = autenticacion.normalizar_correo(correo or "")
    nombre = (nombre or "").strip()
    try:
        validate_email(correo)
    except ValidationError:
        raise ValueError("El correo no es válido.") from None
    if not nombre:
        raise ValueError("La cuenta necesita un nombre.")
    if Usuario.objects.filter(correo=correo).exists():
        raise ReglaIncumplida("CUENTA", "ya existe una cuenta con ese correo")
    ahora = transaccion.hora_de_la_base()
    cuenta = Usuario(correo=correo, nombre=nombre, creado_por_id=actor.pk, creado_en=ahora)
    cuenta.set_unusable_password()
    cuenta.save(force_insert=True)
    codigo, vence_en = _emitir_codigo(cuenta.pk, ALTA, actor.pk, ahora)
    return AltaResultado(cuenta.pk, vence_en, codigo)


@_servicio
def modificar_cuenta(actor, usuario_id, *, nombre: str) -> CuentaResultado:
    """Solo el perfil (nombre). Roles, credenciales y estado tienen sus propios servicios."""
    nombre = (nombre or "").strip()
    if not nombre:
        raise ValueError("La cuenta necesita un nombre.")
    cuenta = _cuenta_bloqueada(_uuid(usuario_id))
    Usuario.objects.filter(pk=cuenta.pk).update(nombre=nombre)
    return _resultado_cuenta(cuenta.pk)


@_servicio
def asignar_rol(actor, usuario_id, rol: str) -> CuentaResultado:
    """Cd13: nadie se asigna roles y la asignación no crea un par excluyente (ExclusionEstatica)."""
    usuario_id = _uuid(usuario_id)
    if usuario_id == actor.pk:
        raise ReglaIncumplida("Cd13", "nadie se asigna roles a sí mismo")
    if not Rol.objects.filter(pk=rol).exists():
        raise ReglaIncumplida("ROL", "el rol no existe")
    cuenta = _cuenta_bloqueada(usuario_id)
    vigentes = _roles_vigentes(cuenta.pk)
    if rol in vigentes:
        raise ReglaIncumplida("ROL", "la cuenta ya tiene ese rol vigente")
    pares = Q(pk__in=[])
    for otro in vigentes:
        pares |= Q(rol_a_id=min(rol, otro), rol_b_id=max(rol, otro))
    if ExclusionEstatica.objects.filter(pares).exists():
        raise ReglaIncumplida("Cd13", "el rol es incompatible con un rol vigente de la cuenta")
    RolUsuario.objects.create(
        usuario_id=cuenta.pk, rol_id=rol, desde=transaccion.hora_de_la_base(), asignado_por_id=actor.pk
    )
    return _resultado_cuenta(cuenta.pk)


@_servicio
def revocar_rol(actor, usuario_id, rol: str) -> CuentaResultado:
    usuario_id = _uuid(usuario_id)
    if usuario_id == actor.pk:
        raise ReglaIncumplida("Cd13", "nadie se revoca roles a sí mismo")
    cuenta = _cuenta_bloqueada(usuario_id, activa=False)
    filas = RolUsuario.objects.filter(usuario_id=cuenta.pk, rol_id=rol, hasta__isnull=True).update(
        hasta=transaccion.hora_de_la_base()
    )
    if filas == 0:
        raise ReglaIncumplida("ROL", "la cuenta no tiene ese rol vigente")
    return _resultado_cuenta(cuenta.pk)


@_servicio
def dar_de_baja_cuenta(actor, usuario_id) -> BajaResultado:
    """Baja lógica: desactiva la cuenta, cierra sus sesiones e invalida sus códigos pendientes.

    Los roles quedan registrados tal como estaban; una cuenta inactiva no inicia sesión.
    """
    usuario_id = _uuid(usuario_id)
    if usuario_id == actor.pk:
        raise ReglaIncumplida("Cd13", "nadie se da de baja a sí mismo")
    cuenta = _cuenta_bloqueada(usuario_id)
    ahora = transaccion.hora_de_la_base()
    Usuario.objects.filter(pk=cuenta.pk).update(activo=False)
    return BajaResultado(cuenta.pk, _cerrar_sesiones(cuenta.pk, ahora), _invalidar_codigos(cuenta.pk, ahora))


# --------------------------------------------------------------------------- ventanas de auditoría


def _exigir_solo_r5(auditor_id) -> None:
    if _roles_vigentes(auditor_id) != {ROL_AUDITOR}:
        raise ReglaIncumplida("Cd23", "la cuenta destino debe tener el rol R5 y solo ese rol")


@_servicio
def solicitar_ventana(actor, auditor_id, inicio: datetime, fin: datetime) -> VentanaResultado:
    """O6.Sv. Cd23: destino solo R5 y fin posterior al inicio. No da acceso hasta que otra persona la abra."""
    if fin <= inicio:
        raise ReglaIncumplida("Cd23", "el fin de la ventana debe ser posterior al inicio")
    auditor = _cuenta_bloqueada(_uuid(auditor_id))
    _exigir_solo_r5(auditor.pk)
    ventana = VentanaAuditoria.objects.create(
        auditor_id=auditor.pk, inicio=inicio, fin=fin, solicitada_por_id=actor.pk,
        solicitada_en=transaccion.hora_de_la_base(),
    )
    return VentanaResultado(ventana.pk, "solicitada")


@_servicio
def abrir_ventana(actor, ventana_id) -> VentanaResultado:
    """O6.Av. Cd23: solicitud pendiente de otra persona, destino solo R5 y, sumando esta ventana, a
    lo sumo waud_dias_anuales días de ventanas abiertas por año calendario (ver usuarios.ventanas).
    """
    visible = VentanaAuditoria.objects.filter(pk=ventana_id).values_list("auditor_id", flat=True).first()
    if visible is None:
        raise ReglaIncumplida("Cd23", "no existe una solicitud de ventana registrada")
    # Bloquear la cuenta del auditor serializa las aperturas de sus ventanas para el conteo anual.
    _cuenta_bloqueada(visible)
    ventana = VentanaAuditoria.objects.select_for_update().get(pk=ventana_id)
    if ventana.abierta_por_id is not None:
        raise ReglaIncumplida("Cd23", "la solicitud ya fue abierta")
    if ventana.solicitada_por_id == actor.pk:
        raise ReglaIncumplida("Cd23", "quien solicita la ventana no la abre")
    _exigir_solo_r5(ventana.auditor_id)
    limite = plazos.leer_parametro_entero(CLAVE_VENTANA_AUDITOR)
    abiertas = VentanaAuditoria.objects.filter(auditor_id=ventana.auditor_id, abierta_por__isnull=False)
    if ventanas.excede_limite(abiertas.values_list("inicio", "fin"), (ventana.inicio, ventana.fin), limite):
        raise ReglaIncumplida("Cd23", f"la cuenta superaría {limite} días de ventana en el año")
    VentanaAuditoria.objects.filter(pk=ventana.pk).update(
        abierta_por_id=actor.pk, abierta_en=transaccion.hora_de_la_base()
    )
    return VentanaResultado(ventana.pk, "abierta")


# --------------------------------------------------------------------------- acceso de emergencia


@_servicio
def autorizar_emergencia(actor, beneficiario_id, rol_suplido: str, *, perfil: str = PERFIL_SOLO_LECTURA) -> EmergenciaResultado:
    """Doble control (Cd24): la primera autorización crea el registro pendiente; la segunda, de otra
    persona con el rol complementario (una R4 y otra R7), lo activa.

    Al activarse vence en min(temg_horas, tope del CHECK emergencia_duracion_maxima) desde now(),
    queda con la revisión pendiente hasta now() + trev_emg_horas y registra un aviso prioritario.
    """
    if perfil != PERFIL_SOLO_LECTURA:
        raise ReglaIncumplida("Cd24", "solo se autoriza el perfil de solo lectura")
    if rol_suplido not in ROLES_SUPLIBLES:
        raise ReglaIncumplida("Cd24", "el rol suplido debe ser R1 o R2")
    beneficiario_id = _uuid(beneficiario_id)
    if beneficiario_id == actor.pk:
        raise ReglaIncumplida("Cd24", "el beneficiario no puede ser uno de los autorizadores")
    roles = _roles_vigentes(actor.pk) & set(ROLES_AUTORIZADORES)
    if len(roles) != 1:
        raise ReglaIncumplida("Cd24", "quien autoriza debe tener R4 o R7 vigente")
    campo = "autorizado_por_r4_id" if roles == {"R4"} else "autorizado_por_r7_id"
    beneficiario = _cuenta_bloqueada(beneficiario_id)
    pendiente = AccesoEmergencia.objects.select_for_update().filter(
        beneficiario_id=beneficiario.pk, inicio__isnull=True
    ).first()
    if pendiente is None:
        acceso = AccesoEmergencia.objects.create(
            beneficiario_id=beneficiario.pk, rol_suplido_id=rol_suplido, perfil=perfil, **{campo: actor.pk}
        )
        return EmergenciaResultado(acceso.pk, "pendiente", None, None)
    if pendiente.rol_suplido_id != rol_suplido:
        raise ReglaIncumplida("Cd24", "hay una autorización pendiente para otro rol suplido")
    if actor.pk in (pendiente.autorizado_por_r4_id, pendiente.autorizado_por_r7_id):
        raise ReglaIncumplida("Cd24", "la segunda autorización debe ser de otra persona")
    if getattr(pendiente, campo) is not None:
        raise ReglaIncumplida("Cd24", "la segunda autorización debe venir del rol complementario (R4 y R7)")
    horas = timedelta(hours=float(plazos.leer_parametro(CLAVE_EMERGENCIA_HORAS)))
    revision = timedelta(hours=float(plazos.leer_parametro(CLAVE_REVISION_EMERGENCIA_HORAS)))
    ahora = transaccion.hora_de_la_base()
    vence_en = ahora + min(horas, DURACION_MAXIMA_EMERGENCIA)
    AccesoEmergencia.objects.filter(pk=pendiente.pk).update(
        inicio=ahora, fin=vence_en, revision_vence_en=ahora + revision, **{campo: actor.pk}
    )
    autorizador_r7 = actor.pk if campo == "autorizado_por_r7_id" else pendiente.autorizado_por_r7_id
    alertas.registrar_aviso(
        TIPO_REVISION_EMERGENCIA, autorizador_r7, prioridad=alertas.PRIORITARIA, cuenta_afectada_id=beneficiario.pk,
        detalle={"acceso_id": str(pendiente.pk), "revision_vence_en": (ahora + revision).isoformat()},
    )
    return EmergenciaResultado(pendiente.pk, "activa", vence_en, ahora + revision)


def acceso_emergencia_vigente(usuario_id) -> str | None:
    """Rol suplido de un acceso activado, sin vencer y sin usar; None si no hay ninguno."""
    ahora = transaccion.hora_de_la_base()
    return (
        AccesoEmergencia.objects.filter(
            beneficiario_id=usuario_id, inicio__lte=ahora, fin__gt=ahora, usado_en__isnull=True,
            perfil=PERFIL_SOLO_LECTURA,
        )
        .order_by("-inicio")
        .values_list("rol_suplido_id", flat=True)
        .first()
    )


def consumir_emergencia(usuario_id) -> ConsumoResultado:
    """Marca el uso del acceso vigente (un solo uso). Un segundo uso falla con Cd24.

    El punto de decisión guarda en la sesión el rol suplido y el vencimiento que devuelve.
    """
    try:
        with transaction.atomic():
            ahora = transaccion.hora_de_la_base()
            acceso = (
                AccesoEmergencia.objects.select_for_update()
                .filter(beneficiario_id=usuario_id, inicio__lte=ahora, fin__gt=ahora, perfil=PERFIL_SOLO_LECTURA)
                .order_by("-inicio")
                .first()
            )
            if acceso is None:
                raise ReglaIncumplida("Cd24", "no hay un acceso de emergencia vigente")
            if not AccesoEmergencia.objects.filter(pk=acceso.pk, usado_en__isnull=True).update(usado_en=ahora):
                raise ReglaIncumplida("Cd24", "el acceso de emergencia ya fue usado")
            return ConsumoResultado(acceso.rol_suplido_id, acceso.fin)
    except DatabaseError as error:
        regla = _regla_de_la_base(error)
        if regla is None:
            raise
        raise regla from error


# --------------------------------------------------------------------------- recuperación


@_servicio
def emitir_recuperacion(actor, usuario_id) -> CodigoResultado:
    """O6.Md. Código de recuperación de 30 minutos; invalida los pendientes y avisa a R7."""
    usuario_id = _uuid(usuario_id)
    if usuario_id == actor.pk:
        raise ReglaIncumplida("Cd13", "nadie emite códigos para su propia cuenta")
    cuenta = _cuenta_bloqueada(usuario_id)
    if not cuenta.totp_secreto_cifrado:
        # Sin segundo factor no hay canal independiente: corresponde baja y alta nueva.
        raise ReglaIncumplida("CUENTA", "la cuenta no tiene segundo factor; requiere baja y alta nueva")
    ahora = transaccion.hora_de_la_base()
    codigo, vence_en = _emitir_codigo(cuenta.pk, RECUPERACION, actor.pk, ahora)
    alertas.registrar_aviso(TIPO_RECUPERACION_EMITIDA, actor.pk, cuenta_afectada_id=cuenta.pk)
    return CodigoResultado(cuenta.pk, vence_en, codigo)


def _politica_de_contrasena(contrasena: str, cuenta: Usuario) -> None:
    try:
        validate_password(contrasena, user=cuenta)
    except ValidationError as error:
        raise ReglaIncumplida("CONTRASENA", " ".join(error.messages)) from None


def _canjear(codigo: str, correo: str, contrasena: str, codigo_totp: str | None) -> CanjeResultado | None:
    """None ante cualquier falla, con los intentos fallidos ya registrados."""
    ahora = transaccion.hora_de_la_base()
    cuenta = (
        Usuario.objects.select_for_update()
        .filter(correo=autenticacion.normalizar_correo(correo or ""), activo=True)
        .first()
    )
    pendientes = []
    if cuenta is not None:
        pendientes = list(
            CodigoUnUso.objects.select_for_update().filter(
                usuario_id=cuenta.pk, usado_en__isnull=True,
                intentos_fallidos__lt=MAX_INTENTOS_CODIGO, vence_en__gt=ahora,
            )
        )
    elegido = None
    for pendiente in pendientes:
        if codigos.coincide(pendiente.huella, codigo or ""):
            elegido = pendiente
    if elegido is None:
        # El código no corresponde: cuenta un intento en cada código pendiente de esa cuenta.
        if pendientes:
            CodigoUnUso.objects.filter(pk__in=[p.pk for p in pendientes]).update(
                intentos_fallidos=F("intentos_fallidos") + 1
            )
        else:
            codigos.coincide("0" * 64, codigo or "")
        return None
    if elegido.proposito == RECUPERACION and not (
        codigo_totp and autenticacion.consumir_codigo(cuenta, codigo_totp)
    ):
        CodigoUnUso.objects.filter(pk=elegido.pk).update(intentos_fallidos=F("intentos_fallidos") + 1)
        return None
    _politica_de_contrasena(contrasena, cuenta)
    if not CodigoUnUso.objects.filter(pk=elegido.pk, usado_en__isnull=True).update(usado_en=ahora):
        return None
    _invalidar_codigos(cuenta.pk, ahora)
    cuenta.set_password(contrasena)
    if elegido.proposito == ALTA:
        secreto = totp.generar_secreto()
        Usuario.objects.filter(pk=cuenta.pk).update(
            password=cuenta.password, totp_secreto_cifrado=cifrado.cifrar(secreto, cuenta.pk),
            totp_confirmado=False, totp_ultimo_paso=None, intentos_fallidos=0, bloqueado_hasta=None,
        )
        return CanjeResultado(ALTA, secreto, totp.uri_aprovisionamiento(cuenta.correo, secreto))
    Usuario.objects.filter(pk=cuenta.pk).update(password=cuenta.password, intentos_fallidos=0, bloqueado_hasta=None)
    _cerrar_sesiones(cuenta.pk, ahora)
    return CanjeResultado(RECUPERACION)


def canjear_codigo(codigo: str, *, correo: str, contrasena: str, codigo_totp: str | None = None) -> CanjeResultado:
    """Canje sin sesión de un código de alta o de recuperación.

    Alta: fija la contraseña inicial y genera el secreto TOTP (se confirma en el primer inicio de
    sesión, como en el resto del módulo de autenticación). Recuperación: exige además un código TOTP
    vigente de la cuenta, porque el segundo factor es el canal independiente del administrador, y
    cierra las sesiones de la cuenta. Toda falla del código o del TOTP lanza la misma ReglaIncumplida
    "RECUPERACION"; los intentos fallidos se guardan aunque el canje falle. Una contraseña que no
    cumple la política lanza "CONTRASENA" y no consume el código.
    """
    with transaction.atomic():
        resultado = _canjear(codigo, correo, contrasena, codigo_totp)
    if resultado is None:
        raise ReglaIncumplida(*FALLO_CANJE)
    return resultado
