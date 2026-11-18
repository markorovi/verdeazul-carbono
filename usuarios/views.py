"""Vistas de autenticación: acceso en dos pasos, reautenticación, recuperación, cuenta y salida.

Todos los fallos se ven iguales desde fuera (sin enumeración de cuentas). `next` solo admite rutas
internas. Además del bloqueo por cuenta, el acceso y la recuperación tienen un límite por IP.
"""

import time

from django.contrib.auth import logout
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from interfaz import avisos, limites
from interfaz.errores import respuesta_generica
from interfaz.redireccion import destino_seguro
from interfaz.web import autenticada, publica
from mediciones.errores import ReglaIncumplida
from usuarios import autenticacion
from usuarios import servicios as cuentas
from usuarios.forms import AccesoForm, RecuperacionForm, SegundoFactorForm
from usuarios.models import RolUsuario

MENSAJE_FALLO = "No fue posible iniciar sesión. Verifique sus datos."
MENSAJE_FALLO_CANJE = "No fue posible completar la operación con esos datos."
MENSAJE_REAUTENTICACION = "No fue posible confirmar el código. Verifique sus datos."
CLAVE_DESTINO = "destino_tras_acceso"


def _respuesta_fallo(request, plantilla: str, formulario, contexto=None, mensaje=MENSAJE_FALLO):
    """Misma respuesta para cualquier fallo; el formulario vuelve vacío para no reflejar datos."""
    return render(request, plantilla, {"form": formulario(), "error": mensaje, **(contexto or {})})


@publica
@never_cache
@require_http_methods(["GET", "POST"])
def acceso(request):
    if request.method == "GET":
        siguiente = destino_seguro(request.GET.get("next"))
        return render(request, "usuarios/acceso.html", {"form": AccesoForm(), "siguiente": siguiente})
    siguiente = destino_seguro(request.POST.get("next"))
    if limites.limitado(request, limites.ACCESO):
        return respuesta_generica(429)
    form = AccesoForm(request.POST)
    usuario = None
    if form.is_valid():
        usuario = autenticacion.primer_factor(
            request, form.cleaned_data["correo"], form.cleaned_data["password"]
        )
    if usuario is None:
        limites.registrar_fallo(request, limites.ACCESO)
        return _respuesta_fallo(request, "usuarios/acceso.html", AccesoForm, {"siguiente": siguiente})
    autenticacion.iniciar_pre_autenticacion(request, usuario)
    request.session[CLAVE_DESTINO] = siguiente
    return redirect("segundo_factor")


@publica
@never_cache
@require_http_methods(["GET", "POST"])
def segundo_factor(request):
    usuario = autenticacion.usuario_pre_autenticado(request)
    if usuario is None:
        return redirect("acceso")
    if request.method == "GET":
        return render(request, "usuarios/segundo_factor.html", {"form": SegundoFactorForm()})
    if limites.limitado(request, limites.ACCESO):
        return respuesta_generica(429)
    form = SegundoFactorForm(request.POST)
    codigo = form.cleaned_data["codigo"] if form.is_valid() else ""
    # Acceso anterior: los avisos al titular cubren lo ocurrido desde entonces.
    anterior = usuario.last_login
    if not autenticacion.segundo_factor(request, usuario, codigo):
        limites.registrar_fallo(request, limites.ACCESO)
        return _respuesta_fallo(request, "usuarios/segundo_factor.html", SegundoFactorForm)
    destino = destino_seguro(request.session.pop(CLAVE_DESTINO, None))
    try:
        avisos.guardar(request, avisos.desde(usuario.pk, anterior))
    except Exception:
        avisos.guardar(request, ["No se pudo comprobar si hubo cambios en su cuenta desde su último acceso."])
    return redirect(destino)


@autenticada
@never_cache
@require_http_methods(["GET", "POST"])
def reautenticar(request):
    """Segundo factor reciente para las operaciones que lo exigen (900 s). No reenvía nada: vuelve a
    la ruta indicada, donde la operación pendiente se muestra para confirmarla."""
    siguiente = destino_seguro(request.GET.get("next") or request.POST.get("next"))
    if request.method == "GET":
        return render(request, "usuarios/reautenticar.html", {"form": SegundoFactorForm(), "siguiente": siguiente})
    usuario = request.user
    usuario.refresh_from_db(fields=["activo", "bloqueado_hasta", "totp_secreto_cifrado"])
    if not usuario.activo or autenticacion.esta_bloqueado(usuario):
        logout(request)
        return redirect("acceso")
    form = SegundoFactorForm(request.POST)
    codigo = form.cleaned_data["codigo"] if form.is_valid() else ""
    if not autenticacion.consumir_codigo(usuario, codigo):
        autenticacion.registrar_fallo(usuario.pk, "totp_invalido")
        usuario.refresh_from_db(fields=["bloqueado_hasta"])
        if autenticacion.esta_bloqueado(usuario):
            logout(request)
            return redirect("acceso")
        return _respuesta_fallo(request, "usuarios/reautenticar.html", SegundoFactorForm, {"siguiente": siguiente},
                                MENSAJE_REAUTENTICACION)
    request.session[autenticacion.CLAVE_MFA] = time.time()
    autenticacion.registrar_evento("reautenticacion", "exito", usuario.pk)
    return redirect(siguiente)


@publica
@never_cache
@require_http_methods(["GET", "POST"])
def recuperar(request):
    """Canje sin sesión de un código de alta o de recuperación (usuarios.servicios.canjear_codigo)."""
    if request.method == "GET":
        return render(request, "usuarios/recuperar.html", {"form": RecuperacionForm()})
    if limites.limitado(request, limites.RECUPERACION):
        return respuesta_generica(429)
    form = RecuperacionForm(request.POST)
    if not form.is_valid():
        limites.registrar_fallo(request, limites.RECUPERACION)
        return _respuesta_fallo(request, "usuarios/recuperar.html", RecuperacionForm, mensaje=MENSAJE_FALLO_CANJE)
    datos = form.cleaned_data
    try:
        canje = cuentas.canjear_codigo(datos["codigo"], correo=datos["correo"], contrasena=datos["contrasena"],
                                       codigo_totp=datos["codigo_totp"] or None)
    except ReglaIncumplida as error:
        if error.condicion == "CONTRASENA":
            return render(request, "usuarios/recuperar.html", {
                "form": RecuperacionForm(), "error": "La contraseña nueva no cumple la política de contraseñas."})
        limites.registrar_fallo(request, limites.RECUPERACION)
        return _respuesta_fallo(request, "usuarios/recuperar.html", RecuperacionForm, mensaje=MENSAJE_FALLO_CANJE)
    return render(request, "usuarios/recuperado.html", {
        "alta": canje.proposito == cuentas.ALTA, "secreto": canje.secreto_totp, "uri": canje.uri_totp})


@autenticada
@never_cache
@require_POST
def salida(request):
    usuario_id = request.user.pk if request.user.is_authenticated else None
    logout(request)
    if usuario_id:
        autenticacion.registrar_evento("salida", "solicitada", usuario_id)
    return redirect("acceso")


@autenticada
@never_cache
@require_http_methods(["GET"])
def cuenta(request):
    roles = list(
        RolUsuario.objects.filter(usuario=request.user, hasta__isnull=True)
        .order_by("rol_id")
        .values_list("rol_id", "rol__nombre")
    )
    return render(request, "usuarios/cuenta.html", {"roles": roles, "avisos": avisos.retirar(request)})
