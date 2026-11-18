"""Aplicación WSGI del servicio de bitácora: solo anexar y consultar.

Rutas: POST /eventos, GET /eventos, GET /exportar, GET /puntos, POST /puntos, POST /verificar y
GET /salud. Cualquier otra ruta responde 404 y otro método en una ruta conocida, 405.

El servicio no autentica por sí mismo: en la nube es privado (Cloud Run con IAM; solo la cuenta de
servicio de la aplicación tiene roles/run.invoker y Cloud Run valida el token de identidad antes de
la petición) y en dev escucha solo en loopback. No debe exponerse públicamente.
"""

from __future__ import annotations

import json
import logging
from urllib.parse import parse_qs

from bitacora_svc import almacen as almacenes
from bitacora_svc.contrato import CLASES, MAX_BYTES_CUERPO, EventoInvalido, decodificar_cuerpo
from bitacora_svc.servicio import Configuracion, RelojRetrocede, Servicio

registro = logging.getLogger("bitacora_svc")

ESTADOS = {200: "200 OK", 201: "201 Created", 400: "400 Bad Request", 404: "404 Not Found",
           405: "405 Method Not Allowed", 411: "411 Length Required", 413: "413 Payload Too Large",
           503: "503 Service Unavailable"}


class _Respuesta(Exception):
    def __init__(self, estado: int, cuerpo: dict):
        self.estado, self.cuerpo = estado, cuerpo


def _json(estado: int, cuerpo, start_response):
    datos = json.dumps(cuerpo, ensure_ascii=False).encode("utf-8")
    start_response(ESTADOS[estado], [("Content-Type", "application/json; charset=utf-8"),
                                     ("Content-Length", str(len(datos))), ("Cache-Control", "no-store")])
    return [datos]


def _leer_cuerpo(environ) -> bytes:
    try:
        largo = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        raise _Respuesta(400, {"error": "cuerpo_invalido"}) from None
    if largo > MAX_BYTES_CUERPO:
        raise _Respuesta(413, {"error": "cuerpo_demasiado_grande"})
    return environ["wsgi.input"].read(largo) if largo > 0 else b""


def _parametros(environ) -> dict:
    crudos = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=False)
    filtros: dict = {}
    for clave in ("usuario_id", "objeto_tipo", "objeto_id", "orden"):
        if clave in crudos:
            filtros[clave] = crudos[clave][0][:64]
    if "clase" in crudos:
        clases = [c for c in crudos["clase"] if c in CLASES]
        if len(clases) != len(crudos["clase"]):
            raise _Respuesta(400, {"error": "parametro_invalido", "parametro": "clase"})
        filtros["clases"] = clases
    for clave in ("desde", "hasta", "limite"):
        if clave in crudos:
            try:
                filtros[clave] = int(crudos[clave][0])
            except ValueError:
                raise _Respuesta(400, {"error": "parametro_invalido", "parametro": clave}) from None
    return filtros


class Aplicacion:
    def __init__(self, servicio: Servicio):
        self.servicio = servicio
        self.rutas = {
            "/eventos": {"POST": self.anexar, "GET": self.consultar},
            "/exportar": {"GET": self.exportar},
            "/puntos": {"GET": self.listar_puntos, "POST": self.crear_punto},
            "/verificar": {"POST": self.verificar},
            "/salud": {"GET": self.salud},
        }

    def __call__(self, environ, start_response):
        ruta = environ.get("PATH_INFO", "")
        metodos = self.rutas.get(ruta)
        if metodos is None:
            return _json(404, {"error": "no_encontrado"}, start_response)
        manejador = metodos.get(environ.get("REQUEST_METHOD", ""))
        if manejador is None:
            return _json(405, {"error": "metodo_no_permitido"}, start_response)
        try:
            return manejador(environ, start_response)
        except _Respuesta as respuesta:
            return _json(respuesta.estado, respuesta.cuerpo, start_response)
        except EventoInvalido as error:
            estado = 413 if error.motivo == "cuerpo demasiado grande" else 400
            return _json(estado, {"error": "evento_invalido", "campo": error.campo}, start_response)
        except Exception as error:
            # Sin detalles internos hacia el cliente; en el registro, solo la clase del error.
            registro.warning(json.dumps({"evento": "error", "ruta": ruta, "clase": type(error).__name__}))
            return _json(503, {"error": "no_disponible"}, start_response)

    def anexar(self, environ, start_response):
        evento = decodificar_cuerpo(_leer_cuerpo(environ))
        try:
            seq, hash_evento = self.servicio.anexar(evento)
        except RelojRetrocede:
            raise _Respuesta(503, {"error": "reloj"}) from None
        return _json(201, {"seq": seq, "hash": hash_evento}, start_response)

    def consultar(self, environ, start_response):
        return _json(200, {"eventos": self.servicio.consultar(_parametros(environ))}, start_response)

    def exportar(self, environ, start_response):
        filtros = _parametros(environ)
        lineas = b"".join(self.servicio.exportar(filtros.get("desde", 1), filtros.get("hasta")))
        start_response("200 OK", [("Content-Type", "application/x-ndjson; charset=utf-8"),
                                  ("Content-Length", str(len(lineas))), ("Cache-Control", "no-store")])
        return [lineas]

    def listar_puntos(self, environ, start_response):
        return _json(200, {"puntos": self.servicio.puntos()}, start_response)

    def crear_punto(self, environ, start_response):
        try:
            documento, creado = self.servicio.crear_punto()
        except ValueError:
            raise _Respuesta(400, {"error": "sin_eventos"}) from None
        except almacenes.AlmacenNoDisponible:
            raise _Respuesta(503, {"error": "almacen_no_disponible"}) from None
        return _json(201 if creado else 200, documento, start_response)

    def verificar(self, environ, start_response):
        return _json(200, self.servicio.verificar(), start_response)

    def salud(self, environ, start_response):
        return _json(200, self.servicio.salud(), start_response)


def crear_aplicacion(configuracion: Configuracion) -> Aplicacion:
    return Aplicacion(Servicio(configuracion))


class _AplicacionDesdeEntorno:
    """Punto de entrada de gunicorn (bitacora_svc.app:aplicacion): la configuración se lee del
    entorno en la primera petición, así importar el módulo no exige las llaves."""

    def __init__(self):
        self._app = None

    def __call__(self, environ, start_response):
        if self._app is None:
            self._app = crear_aplicacion(Configuracion.desde_entorno())
        return self._app(environ, start_response)


aplicacion = _AplicacionDesdeEntorno()
