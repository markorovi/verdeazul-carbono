"""Autenticación en dos pasos: contraseña (Argon2id) y código TOTP obligatorio.

Todos los fallos se ven iguales desde fuera; el motivo real solo queda en el registro de eventos.
"""

import logging
import secrets
import time
from datetime import timedelta
from functools import lru_cache

from django.contrib.auth import authenticate, login
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password, make_password
from django.db.models import Case, F, Q, Value, When
from django.db.models.functions import Least
from django.utils import timezone

from usuarios import cifrado, totp
from usuarios.models import Usuario

MAX_INTENTOS = 5
BLOQUEO_MINUTOS = 15
PRE_AUTH_SEGUNDOS = 300

CLAVE_PRE_AUTH = "pre_auth"
CLAVE_MFA = "mfa_en"
RUTA_BACKEND = "usuarios.autenticacion.BackendCorreo"

logger = logging.getLogger("verdeazul.autenticacion")


EVENTO_BLOQUEO = "bloqueo"
# Evento local -> eventos de bitácora (acción, resultado).
EVENTOS_DE_BITACORA = {
    ("acceso_exitoso", None): (("segundo_factor", "exito"), ("inicio_sesion", "exito")),
    ("acceso_fallido", "totp_invalido"): (("segundo_factor", "fallo"),),
    ("acceso_fallido", None): (("inicio_sesion", "fallo"),),
    (EVENTO_BLOQUEO, None): (("bloqueo", "exito"),),
}


def _a_bitacora(evento: str, motivo: str, usuario_id) -> None:
    """Mejor esfuerzo: si la bitácora no responde, el inicio de sesión sigue y queda un registro
    local del fallo, sin datos sensibles (solo el evento y la clase del error)."""
    pares = EVENTOS_DE_BITACORA.get((evento, motivo)) or EVENTOS_DE_BITACORA.get((evento, None), ())
    for accion, resultado in pares:
        datos = {"accion": accion, "origen": "autenticacion", "resultado": resultado, "motivo": motivo}
        if usuario_id is not None:
            datos["usuario_id"] = str(usuario_id)
        try:
            from autorizacion.cliente_bitacora import cliente_configurado

            cliente_configurado().registrar(datos)
        except Exception as error:
            logger.warning("evento=bitacora_no_disponible origen=autenticacion accion=%s clase=%s",
                           accion, type(error).__name__)


def registrar_evento(evento: str, motivo: str, usuario_id=None) -> None:
    """Nunca recibe contraseñas, códigos, secretos ni correos de cuentas inexistentes."""
    logger.info("evento=%s motivo=%s usuario=%s", evento, motivo, usuario_id or "-")
    _a_bitacora(evento, motivo, usuario_id)


@lru_cache(maxsize=1)
def _hash_ficticio() -> str:
    return make_password(secrets.token_urlsafe(32))


def normalizar_correo(correo: str) -> str:
    return correo.strip().lower()


def esta_bloqueado(usuario: Usuario) -> bool:
    return usuario.bloqueado_hasta is not None and usuario.bloqueado_hasta > timezone.now()


def registrar_fallo(usuario_id, motivo: str) -> None:
    """Suma un intento fallido y bloquea al llegar a MAX_INTENTOS, en un solo UPDATE atómico."""
    bloqueo = timezone.now() + timedelta(minutes=BLOQUEO_MINUTOS)
    Usuario.objects.filter(pk=usuario_id).update(
        intentos_fallidos=Least(F("intentos_fallidos") + 1, Value(MAX_INTENTOS)),
        bloqueado_hasta=Case(
            When(intentos_fallidos__gte=MAX_INTENTOS - 1, then=Value(bloqueo)),
            default=F("bloqueado_hasta"),
        ),
    )
    registrar_evento("acceso_fallido", motivo, usuario_id)
    if Usuario.objects.filter(pk=usuario_id, bloqueado_hasta=bloqueo).exists():
        registrar_evento(EVENTO_BLOQUEO, "maximo_intentos", usuario_id)


class BackendCorreo(BaseBackend):
    """Autentica por correo y contraseña. No inicia sesión: eso ocurre tras el código TOTP."""

    def authenticate(self, request, correo=None, password=None, **kwargs):
        if correo is None:
            correo = kwargs.get(Usuario.USERNAME_FIELD)
        if not correo or password is None:
            return None
        usuario = Usuario.objects.filter(correo=normalizar_correo(correo)).first()
        motivo = None
        if usuario is None:
            motivo = "usuario_inexistente"
        elif not usuario.activo:
            motivo = "inactivo"
        elif esta_bloqueado(usuario):
            motivo = "bloqueado"
        if motivo:
            # Misma verificación costosa que una cuenta real, para no delatar el motivo por tiempo.
            check_password(password, _hash_ficticio())
            registrar_evento("acceso_fallido", motivo, usuario.pk if usuario else None)
            return None
        if not usuario.check_password(password):
            registrar_fallo(usuario.pk, "contrasena_invalida")
            return None
        return usuario

    def get_user(self, user_id):
        usuario = Usuario.objects.filter(pk=user_id).first()
        return usuario if usuario is not None and usuario.activo else None


def primer_factor(request, correo: str, password: str) -> Usuario | None:
    """Contraseña correcta y cuenta con TOTP; si no, None."""
    usuario = authenticate(request, correo=correo, password=password)
    if usuario is None:
        return None
    if not usuario.totp_secreto_cifrado:
        registrar_evento("acceso_fallido", "sin_totp", usuario.pk)
        return None
    return usuario


def iniciar_pre_autenticacion(request, usuario: Usuario) -> None:
    """Estado intermedio del paso 1. No inicia sesión."""
    request.session.cycle_key()
    request.session[CLAVE_PRE_AUTH] = {
        "usuario": str(usuario.pk),
        "expira": time.time() + PRE_AUTH_SEGUNDOS,
    }


def usuario_pre_autenticado(request) -> Usuario | None:
    """Usuario del estado intermedio vigente; si falta o expiró, lo borra y devuelve None."""
    datos = request.session.get(CLAVE_PRE_AUTH)
    if not isinstance(datos, dict) or not isinstance(datos.get("expira"), (int, float)):
        request.session.pop(CLAVE_PRE_AUTH, None)
        return None
    if datos["expira"] < time.time():
        request.session.pop(CLAVE_PRE_AUTH, None)
        return None
    return Usuario.objects.filter(pk=datos.get("usuario")).first()


def consumir_codigo(usuario: Usuario, codigo: str, instante: float | None = None) -> bool:
    """Acepta el código solo si su paso es posterior al último usado (evita reutilizarlo)."""
    if not usuario.totp_secreto_cifrado:
        return False
    secreto = cifrado.descifrar(usuario.totp_secreto_cifrado, usuario.pk)
    paso = totp.verificar(secreto, codigo, time.time() if instante is None else instante)
    if paso is None:
        return False
    filas = (
        Usuario.objects.filter(pk=usuario.pk)
        .filter(Q(totp_ultimo_paso__isnull=True) | Q(totp_ultimo_paso__lt=paso))
        .update(totp_ultimo_paso=paso)
    )
    return filas == 1


def completar_inicio_sesion(request, usuario: Usuario) -> None:
    request.session.pop(CLAVE_PRE_AUTH, None)
    login(request, usuario, backend=RUTA_BACKEND)
    request.session.cycle_key()
    request.session[CLAVE_MFA] = time.time()
    Usuario.objects.filter(pk=usuario.pk).update(
        totp_confirmado=True, intentos_fallidos=0, bloqueado_hasta=None
    )
    registrar_evento("acceso_exitoso", "exito", usuario.pk)


def segundo_factor(request, usuario: Usuario, codigo: str) -> bool:
    """Verifica el código TOTP del usuario pre-autenticado e inicia sesión si es válido."""
    usuario.refresh_from_db(fields=["activo", "bloqueado_hasta", "totp_secreto_cifrado"])
    if not usuario.activo or esta_bloqueado(usuario):
        registrar_evento("acceso_fallido", "bloqueado" if usuario.activo else "inactivo", usuario.pk)
        return False
    if not consumir_codigo(usuario, codigo):
        registrar_fallo(usuario.pk, "totp_invalido")
        return False
    completar_inicio_sesion(request, usuario)
    return True


def mfa_reciente(request, max_segundos: int) -> bool:
    """True si el segundo factor de esta sesión se completó hace max_segundos o menos."""
    momento = request.session.get(CLAVE_MFA)
    return isinstance(momento, (int, float)) and 0 <= time.time() - momento <= max_segundos
