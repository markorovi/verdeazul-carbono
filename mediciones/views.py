"""Rutas públicas de la firma de certificados: clave pública y verificación.

No requieren sesión. La huella confiable es siempre la de la clave de firma configurada.
"""

import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from mediciones import firma

LIMITE_BYTES = 65536
NO_DISPONIBLE = {"estado": "no_disponible", "detalle": "La verificación no está disponible."}


def _huella_confiable() -> str | None:
    try:
        return firma.huella_publica()
    except firma.ClaveDeFirmaNoConfigurada:
        return None


def _respuesta(estado: str, detalle: str, codigo: int = 200) -> JsonResponse:
    return JsonResponse({"estado": estado, "detalle": detalle}, status=codigo)


def _verificar_texto(texto: str, huella: str) -> firma.Resultado:
    if len(texto.encode("utf-8")) > LIMITE_BYTES:
        return firma.Resultado(firma.ESTADO_FORMATO_INVALIDO, f"el certificado supera {LIMITE_BYTES} bytes")
    try:
        documento = json.loads(texto)
    except ValueError:
        return firma.Resultado(firma.ESTADO_FORMATO_INVALIDO, "el texto no es JSON válido")
    return firma.verificar(documento, huella)


@require_GET
def clave_publica(request):
    try:
        datos = {
            "alg": firma.ALG,
            "public_key": firma.clave_publica_b64(),
            "huella_sha256": firma.huella_publica(),
            "key_id": firma.key_id(),
        }
    except firma.ClaveDeFirmaNoConfigurada:
        return JsonResponse(NO_DISPONIBLE, status=503)
    return JsonResponse(datos)


@require_http_methods(["GET", "POST"])
def verificar(request):
    huella = _huella_confiable()
    if huella is None:
        return render(request, "mediciones/verificar.html", {"no_disponible": True}, status=503)
    contexto = {"texto": "", "resultado": None}
    if request.method == "POST":
        contexto["texto"] = request.POST.get("certificado", "")
        contexto["resultado"] = _verificar_texto(contexto["texto"], huella)
    return render(request, "mediciones/verificar.html", contexto)


# Única vista sin CSRF: la consumen clientes externos sin sesión ni formulario, y no cambia estado.
@csrf_exempt
@require_POST
def verificar_api(request):
    huella = _huella_confiable()
    if huella is None:
        return JsonResponse(NO_DISPONIBLE, status=503)
    if request.content_type != "application/json":
        return _respuesta(firma.ESTADO_FORMATO_INVALIDO, "se exige Content-Type application/json", 415)
    try:
        declarado = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        declarado = 0
    if declarado > LIMITE_BYTES:
        return _respuesta(firma.ESTADO_FORMATO_INVALIDO, f"el cuerpo supera {LIMITE_BYTES} bytes", 413)
    cuerpo = request.read(LIMITE_BYTES + 1)
    if len(cuerpo) > LIMITE_BYTES:
        return _respuesta(firma.ESTADO_FORMATO_INVALIDO, f"el cuerpo supera {LIMITE_BYTES} bytes", 413)
    try:
        documento = json.loads(cuerpo.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _respuesta(firma.ESTADO_FORMATO_INVALIDO, "el cuerpo no es JSON válido", 400)
    resultado = firma.verificar(documento, huella)
    return _respuesta(resultado.estado, resultado.detalle)
