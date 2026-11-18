"""Rutas públicas de la firma de certificados: clave pública y verificación.

No requieren sesión. La verificación muestra por separado dos resultados:
1. Integridad: la firma corresponde al payload con la clave incrustada en el documento.
2. Emisor: la clave incrustada es la publicada por Verdeazul (misma huella SHA-256).
Ninguna ruta está exenta de CSRF: la verificación es un formulario. El texto enviado no se repite en
la respuesta y hay un límite de peticiones por IP.
"""

import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_http_methods

from interfaz import limites
from interfaz.errores import respuesta_generica
from interfaz.web import publica
from mediciones import firma

LIMITE_BYTES = 65536
NO_DISPONIBLE = {"estado": "no_disponible", "detalle": "La verificación no está disponible."}

INTEGRO_VERDEAZUL = "integro_verdeazul"
INTEGRO_OTRA_CLAVE = "integro_otra_clave"
ALTERADO = "alterado"
FORMATO_INVALIDO = "formato_invalido"
CONCLUSIONES = {
    INTEGRO_VERDEAZUL: "Íntegro y emitido por Verdeazul.",
    INTEGRO_OTRA_CLAVE: "Íntegro, pero firmado con otra clave: no lo emitió Verdeazul.",
    ALTERADO: "Alterado: la firma no corresponde al contenido.",
    FORMATO_INVALIDO: "Formato inválido: no es un certificado de Verdeazul.",
}
AVISO_ENVOLTORIO = "Se verificó el objeto certificado; estado y trazabilidad no están firmados."


def _huella_confiable() -> str | None:
    try:
        return firma.huella_publica()
    except firma.ClaveDeFirmaNoConfigurada:
        return None


def _datos_publicos() -> dict:
    return {
        "alg": firma.ALG,
        "public_key": firma.clave_publica_b64(),
        "huella_sha256": firma.huella_publica(),
        "key_id": firma.key_id(),
    }


def evaluar(texto: str, huella: str) -> dict:
    """Integridad y emisor por separado, más la conclusión. Solo estados y textos fijos.

    Acepta también el archivo exportado (O3.Ex): se verifica su objeto certificado y "envoltorio"
    indica que estado y trazabilidad quedaron fuera de la verificación.
    """
    try:
        documento = json.loads(texto)
    except ValueError:
        documento = None
    certificado = firma.objeto_a_verificar(documento)
    envoltorio = certificado is not documento
    integridad = firma.verificar(certificado, None)
    if integridad.estado == firma.ESTADO_FORMATO_INVALIDO:
        return {"conclusion": FORMATO_INVALIDO, "estado": integridad.estado, "integridad": None, "emisor": None,
                "envoltorio": envoltorio}
    if integridad.estado == firma.ESTADO_FIRMA_INVALIDA:
        return {"conclusion": ALTERADO, "estado": integridad.estado, "integridad": False, "emisor": None,
                "envoltorio": envoltorio}
    emisor = firma.verificar(certificado, huella)
    propio = emisor.estado == firma.ESTADO_VALIDO
    return {"conclusion": INTEGRO_VERDEAZUL if propio else INTEGRO_OTRA_CLAVE, "estado": emisor.estado,
            "integridad": True, "emisor": propio, "envoltorio": envoltorio}


def _texto_enviado(request) -> tuple[str | None, int]:
    """El archivo tiene prioridad sobre el texto pegado. Devuelve (texto, código HTTP)."""
    archivo = request.FILES.get("archivo")
    if archivo is not None:
        if archivo.size > LIMITE_BYTES:
            return None, 413
        contenido = archivo.read(LIMITE_BYTES + 1)
        if len(contenido) > LIMITE_BYTES:
            return None, 413
        try:
            return contenido.decode("utf-8"), 200
        except UnicodeDecodeError:
            return "", 200
    texto = request.POST.get("certificado", "")
    if len(texto.encode("utf-8")) > LIMITE_BYTES:
        return None, 413
    return texto, 200


@publica
@require_GET
def clave_publica(request):
    try:
        datos = _datos_publicos()
    except firma.ClaveDeFirmaNoConfigurada:
        return JsonResponse(NO_DISPONIBLE, status=503)
    return JsonResponse(datos)


@publica
@require_GET
def clave_publica_pagina(request):
    """La clave pública y su huella SHA-256; nunca la clave privada ni la variable que la contiene."""
    try:
        datos = _datos_publicos()
    except firma.ClaveDeFirmaNoConfigurada:
        return render(request, "mediciones/clave_publica.html", {"no_disponible": True}, status=503)
    return render(request, "mediciones/clave_publica.html", {"datos": datos})


@publica
@require_http_methods(["GET", "POST"])
def verificar(request):
    huella = _huella_confiable()
    if huella is None:
        return render(request, "mediciones/verificar.html", {"no_disponible": True}, status=503)
    contexto = {"resultado": None, "limite": LIMITE_BYTES, "conclusiones": CONCLUSIONES}
    if request.method == "POST":
        if not limites.VERIFICACION.permitir(request):
            return respuesta_generica(429)
        texto, codigo = _texto_enviado(request)
        if texto is None:
            return render(request, "mediciones/verificar.html", {**contexto, "demasiado_grande": True}, status=codigo)
        contexto["resultado"] = evaluar(texto, huella)
        contexto["mensaje"] = CONCLUSIONES[contexto["resultado"]["conclusion"]]
        if contexto["resultado"]["envoltorio"]:
            contexto["aviso"] = AVISO_ENVOLTORIO
    return render(request, "mediciones/verificar.html", contexto)
