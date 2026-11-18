"""Middleware de endurecimiento: límite del cuerpo y encabezados de seguridad de toda respuesta."""

from __future__ import annotations

from django.conf import settings

from interfaz.errores import respuesta_generica

CSP = (
    "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
PREFIJO_ESTATICOS = "/estaticos/"


class LimiteDeCuerpo:
    """Rechaza con 413 todo cuerpo declarado mayor que LIMITE_CUERPO_BYTES, antes de leerlo."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            declarado = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            return respuesta_generica(400)
        if declarado > settings.LIMITE_CUERPO_BYTES:
            return respuesta_generica(413)
        return self.get_response(request)


class EncabezadosDeSeguridad:
    """CSP, Permissions-Policy y no-store en toda respuesta dinámica (la hoja de estilos sí se cachea).

    X-Content-Type-Options, Referrer-Policy, COOP y HSTS los pone SecurityMiddleware y
    X-Frame-Options, XFrameOptionsMiddleware; aquí se completan por si una respuesta se crea antes.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        respuesta = self.get_response(request)
        respuesta.headers["Content-Security-Policy"] = CSP
        respuesta.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
        respuesta.headers.setdefault("Referrer-Policy", settings.SECURE_REFERRER_POLICY)
        respuesta.headers.setdefault("X-Frame-Options", "DENY")
        if not request.path.startswith(PREFIJO_ESTATICOS):
            respuesta.headers["Cache-Control"] = "no-store"
            respuesta.headers["Pragma"] = "no-cache"
        return respuesta
