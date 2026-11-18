"""Cliente del PDP. PDP_BACKEND elige el backend: "opa" (por defecto) o "python" (motor de referencia).

Con OPA, la decisión se pide por HTTP (POST al endpoint de datos de la política) con un timeout de
2 s. En Cloud Run, si OPA_AUDIENCE está definida, se agrega un token de identidad de Google para
el servicio privado de OPA. Cualquier falla (conexión, timeout, HTTP distinto de 200, respuesta mal
formada) lanza PDPNoDisponible y el PEP deniega: nunca se reintenta con otro backend, porque un
cambio de backend silencioso ocultaría una falla de la política.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request

from django.core.exceptions import ImproperlyConfigured

from autorizacion import motor

RUTA_DECISION = "/v1/data/verdeazul/autorizacion/decision"
OPA_URL_LOCAL = "http://127.0.0.1:8181"
TIMEOUT_SEGUNDOS = 2.0
MAX_BYTES_RESPUESTA = 65536
# Un token de identidad dura una hora; se renueva con margen para no usar uno a punto de vencer.
VIDA_TOKEN_SEGUNDOS = 50 * 60
CLAVES_DECISION = {"permitir", "razon", "restricciones", "condiciones_servicio", "proyeccion", "registrar_lectura"}
RESTRICCIONES_VALIDAS = {motor.RESTRICCION_2FA, motor.RESTRICCION_AVISO, motor.RESTRICCION_CERRAR}


class PDPNoDisponible(Exception):
    """El PDP no respondió una decisión válida. El mensaje nunca incluye la entrada ni secretos."""


def validar_decision(decision) -> dict:
    """La salida debe cumplir exactamente el contrato; si no, se trata como falla del PDP."""
    if not isinstance(decision, dict) or set(decision) != CLAVES_DECISION:
        raise PDPNoDisponible("La decisión no tiene exactamente las claves del contrato.")
    if not isinstance(decision["permitir"], bool) or not isinstance(decision["registrar_lectura"], bool):
        raise PDPNoDisponible("permitir y registrar_lectura deben ser booleanos.")
    if decision["razon"] is not None and not isinstance(decision["razon"], str):
        raise PDPNoDisponible("razon debe ser texto o nula.")
    if decision["permitir"] is False and not decision["razon"]:
        raise PDPNoDisponible("Una denegación debe traer su razón.")
    for clave in ("restricciones", "condiciones_servicio"):
        if not isinstance(decision[clave], list) or not all(isinstance(x, str) for x in decision[clave]):
            raise PDPNoDisponible(f"{clave} debe ser una lista de textos.")
    if not set(decision["restricciones"]) <= RESTRICCIONES_VALIDAS:
        raise PDPNoDisponible("restricciones contiene valores fuera del contrato.")
    if decision["proyeccion"] is not None and not isinstance(decision["proyeccion"], str):
        raise PDPNoDisponible("proyeccion debe ser texto o nula.")
    return decision


class MotorPython:
    nombre = "python"

    def decidir(self, entrada: dict) -> dict:
        try:
            return validar_decision(motor.decidir(entrada))
        except PDPNoDisponible:
            raise
        except Exception:
            raise PDPNoDisponible("El motor de referencia falló.") from None


class _TokenDeIdentidad:
    def __init__(self, audiencia: str):
        self.audiencia = audiencia
        self._token = None
        self._vence = 0.0
        self._candado = threading.Lock()

    def valor(self) -> str:
        with self._candado:
            if self._token is None or time.monotonic() >= self._vence:
                # Importación tardía: en dev y en pruebas no hace falta google-auth.
                from google.auth.transport.requests import Request
                from google.oauth2 import id_token

                self._token = id_token.fetch_id_token(Request(), self.audiencia)
                self._vence = time.monotonic() + VIDA_TOKEN_SEGUNDOS
            return self._token


class ClienteOPA:
    nombre = "opa"

    def __init__(self, url: str | None = None, timeout: float = TIMEOUT_SEGUNDOS, audiencia: str | None = None):
        self.url = (url or OPA_URL_LOCAL).rstrip("/") + RUTA_DECISION
        self.timeout = timeout
        self._token = _TokenDeIdentidad(audiencia) if audiencia else None

    def decidir(self, entrada: dict) -> dict:
        cuerpo = json.dumps({"input": entrada}).encode("utf-8")
        solicitud = urllib.request.Request(
            self.url, data=cuerpo, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            if self._token is not None:
                solicitud.add_header("Authorization", f"Bearer {self._token.valor()}")
            with urllib.request.urlopen(solicitud, timeout=self.timeout) as respuesta:
                if respuesta.status != 200:
                    raise PDPNoDisponible(f"OPA respondió HTTP {respuesta.status}.")
                datos = respuesta.read(MAX_BYTES_RESPUESTA + 1)
        except PDPNoDisponible:
            raise
        except urllib.error.HTTPError as error:
            raise PDPNoDisponible(f"OPA respondió HTTP {error.code}.") from None
        except Exception as error:
            raise PDPNoDisponible(f"OPA no respondió ({type(error).__name__}).") from None
        if len(datos) > MAX_BYTES_RESPUESTA:
            raise PDPNoDisponible("La respuesta de OPA es demasiado grande.")
        try:
            resultado = json.loads(datos.decode("utf-8")).get("result")
        except (ValueError, AttributeError):
            raise PDPNoDisponible("La respuesta de OPA no es JSON válido.") from None
        return validar_decision(resultado)


def pdp_configurado():
    backend = os.environ.get("PDP_BACKEND", "opa").strip().lower()
    if backend == "python":
        return MotorPython()
    if backend == "opa":
        return ClienteOPA(os.environ.get("OPA_URL"), audiencia=os.environ.get("OPA_AUDIENCE") or None)
    raise ImproperlyConfigured("PDP_BACKEND debe ser 'opa' o 'python'.")
