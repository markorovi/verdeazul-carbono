"""Páginas de error genéricas: sin trazas, sin rutas, sin datos de la petición."""

from __future__ import annotations

from django.http import HttpResponse
from django.template import loader

MENSAJES = {
    400: ("Solicitud inválida", "La solicitud no se pudo procesar."),
    403: ("Acceso denegado", "No tiene permiso para realizar esta operación."),
    404: ("No encontrado", "La página solicitada no existe."),
    405: ("Método no permitido", "La página no admite ese método."),
    413: ("Solicitud demasiado grande", "El contenido enviado supera el tamaño permitido."),
    429: ("Demasiados intentos", "Se superó el número de intentos permitidos. Intente más tarde."),
    500: ("Error interno", "Ocurrió un error. Intente más tarde."),
    503: ("Servicio no disponible", "El servicio no está disponible en este momento. Intente más tarde."),
}


def respuesta_generica(codigo: int) -> HttpResponse:
    """Se renderiza sin la petición: no depende de la sesión ni de procesadores de contexto."""
    titulo, mensaje = MENSAJES.get(codigo, MENSAJES[500])
    contenido = loader.get_template("interfaz/error.html").render({"titulo": titulo, "mensaje": mensaje})
    return HttpResponse(contenido, status=codigo)


def solicitud_invalida(request, exception=None):
    return respuesta_generica(400)


def acceso_denegado(request, exception=None):
    return respuesta_generica(403)


def no_encontrado(request, exception=None):
    return respuesta_generica(404)


def error_interno(request):
    return respuesta_generica(500)


def csrf_fallido(request, reason=""):
    return respuesta_generica(403)
