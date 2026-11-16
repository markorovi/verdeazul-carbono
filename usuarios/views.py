"""Vistas de autenticación: acceso en dos pasos, cuenta y salida."""

from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from usuarios import autenticacion
from usuarios.forms import AccesoForm, SegundoFactorForm
from usuarios.models import RolUsuario

MENSAJE_FALLO = "No fue posible iniciar sesión. Verifique sus datos."


def _respuesta_fallo(request, plantilla: str, formulario):
    """Misma respuesta para cualquier fallo; el formulario vuelve vacío para no reflejar datos."""
    return render(request, plantilla, {"form": formulario(), "error": MENSAJE_FALLO})


@never_cache
@require_http_methods(["GET", "POST"])
def acceso(request):
    if request.method == "GET":
        return render(request, "usuarios/acceso.html", {"form": AccesoForm()})
    form = AccesoForm(request.POST)
    usuario = None
    if form.is_valid():
        usuario = autenticacion.primer_factor(
            request, form.cleaned_data["correo"], form.cleaned_data["password"]
        )
    if usuario is None:
        return _respuesta_fallo(request, "usuarios/acceso.html", AccesoForm)
    autenticacion.iniciar_pre_autenticacion(request, usuario)
    return redirect("segundo_factor")


@never_cache
@require_http_methods(["GET", "POST"])
def segundo_factor(request):
    usuario = autenticacion.usuario_pre_autenticado(request)
    if usuario is None:
        return redirect("acceso")
    if request.method == "GET":
        return render(request, "usuarios/segundo_factor.html", {"form": SegundoFactorForm()})
    form = SegundoFactorForm(request.POST)
    codigo = form.cleaned_data["codigo"] if form.is_valid() else ""
    if not autenticacion.segundo_factor(request, usuario, codigo):
        return _respuesta_fallo(request, "usuarios/segundo_factor.html", SegundoFactorForm)
    return redirect("cuenta")


@never_cache
@require_POST
def salida(request):
    usuario_id = request.user.pk if request.user.is_authenticated else None
    logout(request)
    if usuario_id:
        autenticacion.registrar_evento("salida", "solicitada", usuario_id)
    return redirect("acceso")


@never_cache
@login_required
def cuenta(request):
    roles = (
        RolUsuario.objects.filter(usuario=request.user, hasta__isnull=True)
        .select_related("rol")
        .order_by("rol_id")
    )
    return render(request, "usuarios/cuenta.html", {"roles": roles})
