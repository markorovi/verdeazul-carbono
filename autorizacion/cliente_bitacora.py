"""Cliente HTTP del servicio de bitácora; implementa el Protocol Bitacora que exige el PEP.

disponible() pide GET /salud con timeout de 1 s; registrar(evento) hace POST /eventos con timeout de
2 s. Cualquier falla de registrar lanza BitacoraNoDisponible y el PEP deniega las operaciones que la
exigen. En la nube el servicio es privado: si BITACORA_AUDIENCE está definida se agrega un token de
identidad de Google, igual que para OPA. La aplicación nunca habla con la base de la bitácora.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from functools import lru_cache
from urllib.parse import urlencode

from django.conf import settings

from autorizacion.bitacora import BitacoraNoDisponible
from autorizacion.pdp import TokenDeIdentidad

TIMEOUT_SALUD = 1.0
TIMEOUT_REGISTRO = 2.0
TIMEOUT_CONSULTA = 10.0
TIMEOUT_VERIFICACION = 60.0
MAX_BYTES_RESPUESTA = 16 * 1024 * 1024
ESTADOS_DISPONIBLES = ("ok", "degradado")


class ClienteBitacora:
    def __init__(self, url: str | None = None, audiencia: str | None = None):
        self.url = (url or getattr(settings, "BITACORA_URL", "") or "").rstrip("/")
        if not self.url:
            raise BitacoraNoDisponible("Falta BITACORA_URL.")
        audiencia = audiencia if audiencia is not None else getattr(settings, "BITACORA_AUDIENCE", None)
        self._token = TokenDeIdentidad(audiencia) if audiencia else None

    def _pedir(self, metodo: str, ruta: str, timeout: float, cuerpo: dict | None = None, consulta: dict | None = None):
        url = self.url + ruta + (f"?{urlencode(consulta, doseq=True)}" if consulta else "")
        datos = json.dumps(cuerpo).encode("utf-8") if cuerpo is not None else None
        solicitud = urllib.request.Request(url, data=datos, method=metodo)
        if datos is not None:
            solicitud.add_header("Content-Type", "application/json")
        try:
            if self._token is not None:
                solicitud.add_header("Authorization", f"Bearer {self._token.valor()}")
            with urllib.request.urlopen(solicitud, timeout=timeout) as respuesta:
                contenido = respuesta.read(MAX_BYTES_RESPUESTA + 1)
                estado = respuesta.status
        except urllib.error.HTTPError as error:
            raise BitacoraNoDisponible(f"La bitácora respondió HTTP {error.code}.") from None
        except Exception as error:
            raise BitacoraNoDisponible(f"La bitácora no respondió ({type(error).__name__}).") from None
        if len(contenido) > MAX_BYTES_RESPUESTA:
            raise BitacoraNoDisponible("La respuesta de la bitácora es demasiado grande.")
        return estado, contenido

    def _json(self, metodo, ruta, timeout, **opciones) -> tuple[int, dict]:
        estado, contenido = self._pedir(metodo, ruta, timeout, **opciones)
        try:
            return estado, json.loads(contenido.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise BitacoraNoDisponible("La respuesta de la bitácora no es JSON válido.") from None

    def disponible(self) -> bool:
        try:
            estado, datos = self._json("GET", "/salud", TIMEOUT_SALUD)
        except BitacoraNoDisponible:
            return False
        return estado == 200 and datos.get("estado") in ESTADOS_DISPONIBLES

    def registrar(self, evento: dict) -> dict:
        estado, datos = self._json("POST", "/eventos", TIMEOUT_REGISTRO, cuerpo=evento)
        if estado != 201 or not isinstance(datos.get("seq"), int):
            raise BitacoraNoDisponible("La bitácora no confirmó el evento.")
        return datos

    def consultar(self, **filtros) -> list[dict]:
        consulta = {k: v for k, v in filtros.items() if v is not None and k != "clases"}
        if filtros.get("clases"):
            consulta["clase"] = list(filtros["clases"])
        return self._json("GET", "/eventos", TIMEOUT_CONSULTA, consulta=consulta)[1]["eventos"]

    def verificar(self) -> dict:
        return self._json("POST", "/verificar", TIMEOUT_VERIFICACION)[1]

    def puntos(self) -> list[dict]:
        return self._json("GET", "/puntos", TIMEOUT_CONSULTA)[1]["puntos"]

    def crear_punto(self) -> dict:
        return self._json("POST", "/puntos", TIMEOUT_CONSULTA)[1]

    def exportar(self, desde: int = 1, hasta: int | None = None) -> bytes:
        consulta = {"desde": desde, **({"hasta": hasta} if hasta is not None else {})}
        return self._pedir("GET", "/exportar", TIMEOUT_CONSULTA, consulta=consulta)[1]


@lru_cache(maxsize=1)
def cliente_configurado() -> ClienteBitacora:
    """Cliente con BITACORA_URL y BITACORA_AUDIENCE; uno por proceso, para reutilizar el token."""
    return ClienteBitacora()


def consultar(pep, sesion, **filtros):
    """Lectura de la bitácora (O7.L). Pasa por el PEP: sin bitácora no se concede (Cd17) y el auditor
    solo lee dentro de su ventana (Cd3). Con una proyección (bitacora_r7), cada evento se filtra con
    la regla de visibilidad de la política (motor.evento_visible, la misma del Rego).
    Devuelve la lista de eventos (seudonimizados) o la denegación del PEP."""
    from autorizacion import motor
    from autorizacion.pep import Denegado

    resultado = pep.decidir("O7.L", sesion)
    if not resultado.permitido:
        return resultado
    proyeccion = resultado.decision["proyeccion"]
    cliente = pep.bitacora if isinstance(pep.bitacora, ClienteBitacora) else ClienteBitacora()
    try:
        if proyeccion is not None:
            regla = motor.politica()["visibilidad_bitacora"].get(proyeccion, {"clases": [], "administracion_objetos": []})
            # Al servicio se le piden solo las clases que pueden quedar visibles; el filtro fino es local.
            posibles = set(regla["clases"]) | ({"administracion"} if regla["administracion_objetos"] else set())
            pedidas = [c for c in (filtros.pop("clases", None) or sorted(posibles)) if c in posibles]
            if not pedidas:
                return []
            eventos = cliente.consultar(clases=pedidas, **filtros)
            return [e for e in eventos if motor.evento_visible(proyeccion, e)]
        return cliente.consultar(**filtros)
    except BitacoraNoDisponible:
        return Denegado("Cd17", "bitácora no disponible")
