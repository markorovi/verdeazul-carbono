"""Contrato del evento de bitácora y de la cadena de hashes.

El cliente envía un evento con un esquema cerrado; el servicio lo valida, agrega seq, sello, clase y
el seudónimo del usuario, lo canoniza y lo encadena:

    hash = SHA-256( hash_previo en hex ASCII || bytes UTF-8 de canonico(evento sin hash ni hash_previo) )
    canonico = JSON con claves ordenadas, separadores (",", ":") y ensure_ascii=False

El hash previo del primer evento es 64 ceros. Solo hay textos, enteros y nulos (nunca números con
decimales), así que el JSON canónico se reproduce exactamente al releerlo. Ver BITACORA.md.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone

CEROS = "0" * 64
MAX_BYTES_CUERPO = 16384
LARGO_SEUDONIMO = 32

CLASE_CERTIFICACION = "certificacion"
CLASE_CONSULTA = "consulta"
CLASE_ACCESO = "acceso"
CLASE_ADMINISTRACION = "administracion"
CLASES = (CLASE_CERTIFICACION, CLASE_CONSULTA, CLASE_ACCESO, CLASE_ADMINISTRACION)
# Retención por clase (política documentada; no hay purga automática).
RETENCION = {
    CLASE_CERTIFICACION: "10 años desde la emisión",
    CLASE_CONSULTA: "24 meses",
    CLASE_ACCESO: "24 meses",
    CLASE_ADMINISTRACION: "10 años",
}

ACCIONES = (
    "intento", "resultado", "denegacion", "lectura", "exportacion",
    "inicio_sesion", "segundo_factor", "bloqueo", "version_politica",
)
CLASE_DE_ACCION = {
    "lectura": CLASE_CONSULTA,
    "exportacion": CLASE_CONSULTA,
    "inicio_sesion": CLASE_ACCESO,
    "segundo_factor": CLASE_ACCESO,
    "bloqueo": CLASE_ACCESO,
    "denegacion": CLASE_ACCESO,
    "version_politica": CLASE_ADMINISTRACION,
}
# Intentos y resultados se clasifican por el objeto de la operación.
CLASE_DE_OBJETO = {
    "O1": CLASE_CERTIFICACION,
    "O2": CLASE_CERTIFICACION,
    "O3": CLASE_CERTIFICACION,
    "O4": CLASE_CERTIFICACION,
    "O5": CLASE_ADMINISTRACION,
    "O6": CLASE_ADMINISTRACION,
    "O7": CLASE_CONSULTA,
    "O8": CLASE_ADMINISTRACION,
}
OPERACIONES_DE_CONSULTA = {"O3.Ex"}

_HEX64 = r"^[0-9a-f]{64}$"
_UUID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"

# Campo -> (patrón o vocabulario, largo máximo). Todos son textos.
CAMPOS = {
    "accion": (ACCIONES, 20),
    "usuario_id": (r"^[0-9A-Za-z-]{1,64}$", 64),
    "rol_activo": (r"^R[1-7](,R[1-7]){0,6}$", 20),
    "sesion": (_HEX64, 64),
    "operacion": (r"^O[1-8]\.[A-Za-z]{1,4}$", 10),
    "servicio": (r"^[a-z_]{1,64}$", 64),
    "objeto_tipo": (
        ("parcela", "medicion", "certificado", "enmienda", "periodo", "finca", "cuenta",
         "alerta", "ventana", "acceso", "politica", "ninguno"),
        20,
    ),
    "objeto_id": (r"^[0-9A-Za-z._-]{1,64}$", 64),
    "finca_id": (_UUID, 36),
    "periodo_id": (_UUID, 36),
    "decision": (("concedido", "denegado"), 10),
    "regla": (r"^(Cd[0-9]{1,2}|defecto|[A-Z]{3,20})$", 20),
    "motivo": (r"^[a-z_]{1,40}$", 40),
    "version_politica": (_HEX64, 64),
    "huella_anterior": (_HEX64, 64),
    "huella_posterior": (_HEX64, 64),
    "huella_exportacion": (_HEX64, 64),
    "origen": (("pep", "autenticacion", "sistema"), 20),
    "resultado": (("exito", "fallo", "concedido", "denegado", "rechazado", "error"), 20),
    "error_clase": (r"^[A-Za-z_][A-Za-z0-9_.]{0,79}$", 80),
}
OBLIGATORIOS = ("accion", "origen", "resultado")
# Campos que calcula el servicio: si el cliente los envía, se descartan sin confiar en ellos.
IGNORADOS = frozenset({"seq", "sello", "fecha", "hash", "hash_previo", "clase", "usuario"})
CAMPOS_DEL_SERVICIO = ("seq", "sello", "clase", "usuario")


class EventoInvalido(ValueError):
    """El evento no cumple el contrato. `campo` es el nombre del campo (nunca su valor)."""

    def __init__(self, motivo: str, campo: str | None = None):
        super().__init__(motivo)
        self.motivo = motivo
        self.campo = campo


def canonico(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def calcular_hash(hash_previo: str, cuerpo_canonico: bytes) -> str:
    return hashlib.sha256(hash_previo.encode("ascii") + cuerpo_canonico).hexdigest()


def hash_de_evento(evento: dict) -> str:
    """Recalcula el hash de un evento exportado (con hash y hash_previo)."""
    cuerpo = {k: v for k, v in evento.items() if k not in ("hash", "hash_previo")}
    return calcular_hash(evento["hash_previo"], canonico(cuerpo))


def formatear_sello(momento: datetime) -> str:
    return momento.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def seudonimo(sal: bytes, identificador: str) -> str:
    """HMAC-SHA256 con la sal del servicio, truncado a 32 hex. Sin la sal no se puede revertir ni
    recalcular; destruirla desasocia a las personas sin tocar la cadena."""
    return hmac.new(sal, identificador.encode("utf-8"), hashlib.sha256).hexdigest()[:LARGO_SEUDONIMO]


def clase_de(evento: dict) -> str:
    accion = evento["accion"]
    if accion in CLASE_DE_ACCION:
        return CLASE_DE_ACCION[accion]
    operacion = evento.get("operacion")
    if not operacion:
        raise EventoInvalido("un intento o resultado necesita la operación", "operacion")
    if operacion in OPERACIONES_DE_CONSULTA or operacion.endswith(".L"):
        return CLASE_CONSULTA
    return CLASE_DE_OBJETO[operacion.split(".", 1)[0]]


def validar(datos) -> dict:
    """Devuelve el evento validado, sin los campos ignorados. Rechaza todo lo demás."""
    if not isinstance(datos, dict):
        raise EventoInvalido("el evento debe ser un objeto JSON")
    evento = {}
    for campo, valor in datos.items():
        if campo in IGNORADOS:
            continue
        if campo not in CAMPOS:
            raise EventoInvalido("campo desconocido", None)
        if valor is None:
            continue
        regla, largo = CAMPOS[campo]
        if not isinstance(valor, str) or len(valor) > largo:
            raise EventoInvalido("tipo o largo inválido", campo)
        valido = valor in regla if isinstance(regla, tuple) else re.fullmatch(regla, valor) is not None
        if not valido:
            raise EventoInvalido("valor fuera del contrato", campo)
        evento[campo] = valor
    for campo in OBLIGATORIOS:
        if campo not in evento:
            raise EventoInvalido("falta un campo obligatorio", campo)
    clase_de(evento)
    return evento


def decodificar_cuerpo(crudo: bytes) -> dict:
    if len(crudo) > MAX_BYTES_CUERPO:
        raise EventoInvalido("cuerpo demasiado grande")
    try:
        datos = json.loads(crudo.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise EventoInvalido("el cuerpo no es JSON válido") from None
    return validar(datos)
