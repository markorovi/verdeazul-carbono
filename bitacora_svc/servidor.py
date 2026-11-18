"""Servidor local con hilos para dev y pruebas. Escucha SOLO en loopback (127.0.0.1).

En la nube el servicio corre con gunicorn (deploy/bitacora/Dockerfile); este servidor no se usa allí.
"""

from __future__ import annotations

import threading
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

LOOPBACK = "127.0.0.1"


class _ServidorConHilos(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


class _ManejadorSilencioso(WSGIRequestHandler):
    def log_message(self, *args):
        """El registro de accesos de wsgiref incluye la URL; el servicio ya registra lo necesario."""


class ServidorLocal:
    def __init__(self, aplicacion, puerto: int = 0):
        self._servidor = make_server(LOOPBACK, puerto, aplicacion, server_class=_ServidorConHilos,
                                     handler_class=_ManejadorSilencioso)
        self.puerto = self._servidor.server_address[1]
        self.url = f"http://{LOOPBACK}:{self.puerto}"
        self._hilo = threading.Thread(target=self._servidor.serve_forever, daemon=True)

    def iniciar(self) -> ServidorLocal:
        self._hilo.start()
        return self

    def esperar(self) -> None:
        self._hilo.join()

    def detener(self) -> None:
        self._servidor.shutdown()
        self._servidor.server_close()
        self._hilo.join(timeout=5)
