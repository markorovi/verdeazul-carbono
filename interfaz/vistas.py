"""Vistas de la interfaz. Solo presentan: toda decisión la toma el PEP (ver interfaz.web).

Las escrituras se generan desde el registro (interfaz.registro), una vista por operación y servicio,
cada una con su @operacion. Las lecturas de objetos ligados a una parcela (mediciones, certificados,
enmiendas y parcelas) deciden fila por fila: una lista nunca se salta Cd9 ni Cd22 y cada parcela
ajena cuenta como una lectura. Las demás (períodos, cuentas, alertas) no dependen de la fila y se
deciden una vez por página.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from django.conf import settings
from django.db import connection, transaction
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import NoReverseMatch, reverse
from django.views.decorators.http import require_GET, require_http_methods

from autorizacion import cliente_bitacora
from autorizacion import pep as pep_modulo
from autorizacion.pip import Objeto
from catalogo.models import Parcela
from interfaz import formularios, registro, serializadores
from interfaz.web import (
    Rechazo,
    autenticada,
    datos_pendientes,
    operacion,
    publica,
)
from mediciones.contexto import como_actor
from mediciones.models import Alerta, Certificado, Enmienda, Medicion, Periodo
from usuarios.models import RolUsuario, Usuario

TAMANO_MAXIMO = 20
PAGINA_BITACORA = 50
ESTATICOS = {"interfaz/estilo.css": ("text/css; charset=utf-8", Path(__file__).resolve().parent / "static" / "interfaz" / "estilo.css")}
REVISIONES = ("O1.Ap", "O1.Dv")
EXPORTACION = "O3.Ex"


# --------------------------------------------------------------------------- utilidades


def _texto(valor) -> str:
    return serializadores._texto(valor)


def ruta_de(entrada: registro.Entrada, objeto_id=None) -> str | None:
    try:
        if entrada.clase == registro.LECTURA:
            return reverse(entrada.ruta_lectura)
        if entrada.con_objeto:
            return reverse(f"op-{entrada.clave}", kwargs={"objeto_id": objeto_id}) if objeto_id else None
        return reverse(f"op-{entrada.clave}")
    except NoReverseMatch:
        return None


def _acciones(tipo: str, ficha: serializadores.Ficha | None) -> list[tuple[str, str]]:
    """Enlaces a las operaciones sobre el objeto. Presentar un enlace no concede nada: el PEP decide."""
    if ficha is None or ficha.objeto_id is None:
        return []
    return [(e.etiqueta, ruta_de(e, ficha.objeto_id)) for e in registro.ENTRADAS
            if e.clase == registro.ESCRITURA and e.objeto == tipo]


def tamano_de_pagina() -> int:
    """LISTA_TAMANO_PAGINA (10 por defecto) es también el tope: ?tamano solo puede pedir menos."""
    return max(1, min(int(getattr(settings, "LISTA_TAMANO_PAGINA", 10)), TAMANO_MAXIMO))


def _paginacion(request) -> tuple[int, int]:
    tope = tamano_de_pagina()
    form = formularios.Pagina(request.GET)
    if not form.is_valid():
        return 1, tope
    return form.cleaned_data["pagina"] or 1, min(form.cleaned_data["tamano"] or tope, tope)


def _ficha(request, tipo: str, objeto_id, proyeccion):
    try:
        with transaction.atomic(), como_actor(request.user.pk):
            return serializadores.POR_TIPO[tipo](objeto_id, proyeccion)
    except serializadores.ProyeccionNoDisponible:
        raise Rechazo(serializadores.denegacion_cd16()) from None


def _campos_resultado(resultado) -> list[tuple[str, str]]:
    """Campos del resultado del servicio; los bytes (contenido exportado) no se muestran."""
    if not dataclasses.is_dataclass(resultado):
        return []
    return [(campo.name.replace("_", " "), _texto(getattr(resultado, campo.name)))
            for campo in dataclasses.fields(resultado) if not isinstance(getattr(resultado, campo.name), bytes)]


def _roles_propios(usuario) -> list[str]:
    return sorted(RolUsuario.objects.filter(usuario_id=usuario.pk, hasta__isnull=True).values_list("rol_id", flat=True))


# --------------------------------------------------------------------------- públicas y de sesión


@publica
@require_GET
def salud(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception:
        return JsonResponse({"estado": "no_disponible"}, status=503)
    return JsonResponse({"estado": "ok"})


@publica
@require_GET
def estatico(request, nombre: str):
    """Lista cerrada de archivos: nada de rutas arbitrarias ni listados de directorio."""
    if nombre not in ESTATICOS:
        raise Http404()
    tipo, archivo = ESTATICOS[nombre]
    respuesta = FileResponse(archivo.open("rb"), content_type=tipo)
    respuesta.headers["Cache-Control"] = "public, max-age=3600"
    return respuesta


@autenticada
@require_GET
def inicio(request):
    return redirect("consola")


@autenticada
@require_GET
def consola(request):
    roles = _roles_propios(request.user)
    propias = set(registro.codigos_de_roles(roles))
    filas = [{"codigo": e.codigo, "etiqueta": e.etiqueta, "clase": e.clase, "clave": e.clave,
              "con_objeto": e.con_objeto, "objeto": e.objeto, "ruta": ruta_de(e)} for e in registro.ENTRADAS]
    return render(request, "interfaz/consola.html", {
        "roles": roles,
        "propias": [f for f in filas if f["codigo"] in propias],
        "otras": filas,
    })


@autenticada
@require_GET
def ir_a_operacion(request):
    form = formularios.IrAOperacion(request.GET)
    if not form.is_valid() or form.cleaned_data["clave"] not in registro.POR_CLAVE:
        return redirect("consola")
    entrada = registro.POR_CLAVE[form.cleaned_data["clave"]]
    if not entrada.con_objeto:
        return redirect("consola")
    return redirect(ruta_de(entrada, form.cleaned_data["objeto"]))


# --------------------------------------------------------------------------- escrituras


def _exportacion(concedido) -> HttpResponse:
    resultado = concedido.resultado
    respuesta = HttpResponse(resultado.contenido, content_type="application/json; charset=utf-8")
    respuesta.headers["Content-Disposition"] = f'attachment; filename="certificado-{resultado.certificado_id}.json"'
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    return respuesta


def _revision(request, objeto_id, pendiente):
    """Pantalla de revisión de R2: la medición (O1.L con su proyección) y la huella que se revisa."""
    concedido = request.operacion.decidir(Objeto("medicion", objeto_id), codigo="O1.L")
    ficha = _ficha(request, "medicion", objeto_id, concedido.decision["proyeccion"])
    if ficha is None:
        raise Rechazo(pep_modulo.Denegado(pep_modulo.DEFECTO, "objeto no visible"))
    with transaction.atomic(), como_actor(request.user.pk):
        huella = serializadores.huella_vigente(objeto_id)
    inicial = pendiente if pendiente else {"huella_revisada": huella or ""}
    return ficha, formularios.Revision(initial=inicial)


def vista_de_escritura(entrada: registro.Entrada):
    @require_http_methods(["GET", "POST"])
    def vista(request, objeto_id=None):
        contexto = {"entrada": entrada, "objeto_id": objeto_id, "ficha": None, "confirmar": False}
        if request.method == "POST":
            form = entrada.formulario(request.POST)
            if not form.is_valid():
                return render(request, "interfaz/formulario.html", {**contexto, "form": form}, status=400)
            request.datos_validados = {nombre: form.data.get(nombre, "") for nombre in form.fields}
            argumentos = entrada.argumentos(form.cleaned_data, objeto_id)
            concedido = request.operacion.ejecutar(servicio=entrada.servicio, **argumentos)
            if entrada.codigo == EXPORTACION:
                return _exportacion(concedido)
            return render(request, "interfaz/resultado.html", {
                "entrada": entrada, "campos": _campos_resultado(concedido.resultado)})
        pendiente = datos_pendientes(request)
        contexto["confirmar"] = pendiente is not None
        if entrada.codigo in REVISIONES:
            contexto["ficha"], form = _revision(request, objeto_id, pendiente)
        else:
            form = entrada.formulario(initial=pendiente) if pendiente else entrada.formulario()
        return render(request, "interfaz/formulario.html", {**contexto, "form": form})

    vista.__name__ = f"operacion_{entrada.clave.replace('.', '_').replace('-', '_')}"
    return operacion(entrada.codigo, objeto=entrada.objeto)(vista)


def vista_denegada_a_todos(entrada: registro.Entrada):
    """Las 9 operaciones que la matriz no da a nadie: pasan por el PEP, que deniega por defecto y lo
    registra en la bitácora. Si el PEP llegara a conceder, la interfaz igual se niega (403)."""

    @require_http_methods(["GET", "POST"])
    def vista(request):
        request.operacion.decidir()
        raise Rechazo(pep_modulo.Denegado(pep_modulo.DEFECTO, "operación sin implementación"))

    vista.__name__ = f"operacion_{entrada.clave.replace('.', '_')}"
    return operacion(entrada.codigo)(vista)


# --------------------------------------------------------------------------- lecturas


def _lista_por_fila(request, tipo: str, consulta, titulo: str):
    """Una decisión del PEP por fila (con su registro de acceso y sus contadores de H2)."""
    pagina, tamano = _paginacion(request)
    inicio_fila = (pagina - 1) * tamano
    with transaction.atomic(), como_actor(request.user.pk):
        ids = list(consulta().values_list("pk", flat=True)[inicio_fila:inicio_fila + tamano + 1])
    fichas = []
    for objeto_id in ids[:tamano]:
        concedido = request.operacion.intentar(Objeto(tipo, objeto_id))
        if concedido is None:
            continue
        ficha = _ficha(request, tipo, objeto_id, concedido.decision["proyeccion"])
        if ficha is not None:
            fichas.append(ficha)
    return _pagina_de_lista(request, tipo, titulo, fichas, pagina, tamano, len(ids) > tamano)


def _lista_unica(request, tipo: str, consulta, titulo: str):
    """Una decisión por página: las condiciones de estas lecturas no dependen de la fila."""
    pagina, tamano = _paginacion(request)
    concedido = request.operacion.decidir(Objeto(tipo))
    inicio_fila = (pagina - 1) * tamano
    with transaction.atomic(), como_actor(request.user.pk):
        ids = list(consulta().values_list("pk", flat=True)[inicio_fila:inicio_fila + tamano + 1])
    fichas = [f for f in (_ficha(request, tipo, i, concedido.decision["proyeccion"]) for i in ids[:tamano]) if f]
    return _pagina_de_lista(request, tipo, titulo, fichas, pagina, tamano, len(ids) > tamano)


def _pagina_de_lista(request, tipo, titulo, fichas, pagina, tamano, hay_mas):
    detalle = DETALLES.get(tipo)
    filas = [{"ficha": f, "ruta": reverse(detalle, kwargs={"objeto_id": f.objeto_id}) if detalle and f.objeto_id else None}
             for f in fichas]
    return render(request, "interfaz/lista.html", {
        "titulo": titulo, "filas": filas, "pagina": pagina, "tamano": tamano,
        "anterior": pagina - 1 if pagina > 1 else None, "siguiente": pagina + 1 if hay_mas else None,
    })


def _detalle(request, tipo: str, objeto_id, titulo: str):
    concedido = request.operacion.decidir()
    ficha = _ficha(request, tipo, objeto_id, concedido.decision["proyeccion"])
    if ficha is None:
        raise Rechazo(pep_modulo.Denegado(pep_modulo.DEFECTO, "objeto no visible"))
    return render(request, "interfaz/detalle.html", {"titulo": titulo, "ficha": ficha, "acciones": _acciones(tipo, ficha)})


@operacion("O1.L")
@require_GET
def lista_mediciones(request):
    return _lista_por_fila(request, "medicion", lambda: Medicion.objects.order_by("-creada_en", "pk"), "Mediciones")


@operacion("O1.L", objeto="medicion")
@require_GET
def detalle_medicion(request, objeto_id):
    return _detalle(request, "medicion", objeto_id, "Medición")


@operacion("O2.L")
@require_GET
def lista_periodos(request):
    return _lista_unica(request, "periodo", lambda: Periodo.objects.order_by("-inicio", "pk"), "Períodos")


@operacion("O2.L", objeto="periodo")
@require_GET
def detalle_periodo(request, objeto_id):
    return _detalle(request, "periodo", objeto_id, "Período")


@operacion("O3.L")
@require_GET
def lista_certificados(request):
    return _lista_por_fila(request, "certificado", lambda: Certificado.objects.order_by("-emitido_en", "pk"),
                           "Certificados")


@operacion("O3.L", objeto="certificado")
@require_GET
def detalle_certificado(request, objeto_id):
    return _detalle(request, "certificado", objeto_id, "Certificado")


@operacion("O4.L")
@require_GET
def lista_enmiendas(request):
    return _lista_por_fila(request, "enmienda", lambda: Enmienda.objects.order_by("-solicitada_en", "pk"), "Enmiendas")


@operacion("O4.L", objeto="enmienda")
@require_GET
def detalle_enmienda(request, objeto_id):
    return _detalle(request, "enmienda", objeto_id, "Enmienda")


@operacion("O5.L")
@require_GET
def lista_parcelas(request):
    return _lista_por_fila(request, "parcela", lambda: Parcela.objects.order_by("finca_id", "codigo", "pk"),
                           "Parcelas")


@operacion("O5.L", objeto="parcela")
@require_GET
def detalle_parcela(request, objeto_id):
    return _detalle(request, "parcela", objeto_id, "Parcela")


@operacion("O5.L", objeto="finca")
@require_GET
def detalle_finca(request, objeto_id):
    return _detalle(request, "finca", objeto_id, "Finca")


@operacion("O6.L")
@require_GET
def lista_cuentas(request):
    return _lista_unica(request, "cuenta", lambda: Usuario.objects.order_by("creado_en", "pk"), "Cuentas")


@operacion("O6.L", objeto="cuenta")
@require_GET
def detalle_cuenta(request, objeto_id):
    return _detalle(request, "cuenta", objeto_id, "Cuenta")


@operacion("O8.L")
@require_GET
def lista_alertas(request):
    return _lista_unica(request, "alerta", lambda: Alerta.objects.order_by("-creada_en", "pk"), "Alertas")


@operacion("O8.L", objeto="alerta")
@require_GET
def detalle_alerta(request, objeto_id):
    return _detalle(request, "alerta", objeto_id, "Alerta")


@operacion("O7.L")
@require_GET
def bitacora(request):
    """R5 dentro de su ventana; R7 con la proyección bitacora_r7. Sin bitácora, 503 genérico."""
    filtro = formularios.FiltroBitacora(request.GET)
    filtros = {"limite": PAGINA_BITACORA, "orden": "desc"}
    if filtro.is_valid() and filtro.cleaned_data["antes_de"]:
        filtros["hasta"] = filtro.cleaned_data["antes_de"] - 1
    op = request.operacion
    try:
        resultado = cliente_bitacora.consultar_con_proyeccion(op.pep, op.sesion, **filtros)
    finally:
        op._guardar()
    if not isinstance(resultado, tuple):
        raise Rechazo(resultado)
    eventos, proyeccion = resultado
    try:
        fichas = [serializadores.evento(e, proyeccion) for e in eventos]
    except serializadores.ProyeccionNoDisponible:
        raise Rechazo(serializadores.denegacion_cd16()) from None
    seqs = [e.get("seq") for e in eventos if isinstance(e.get("seq"), int)]
    return render(request, "interfaz/bitacora.html", {
        "fichas": fichas, "antes_de": min(seqs) if len(seqs) >= PAGINA_BITACORA and min(seqs) > 1 else None})


DETALLES = {
    "medicion": "detalle_medicion", "periodo": "detalle_periodo", "certificado": "detalle_certificado",
    "enmienda": "detalle_enmienda", "parcela": "detalle_parcela", "finca": "detalle_finca",
    "cuenta": "detalle_cuenta", "alerta": "detalle_alerta",
}
