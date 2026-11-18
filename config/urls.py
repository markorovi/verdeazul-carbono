from django.urls import include, path

urlpatterns = [
    path("", include("usuarios.urls")),
    path("", include("mediciones.urls")),
    path("", include("interfaz.urls")),
]

handler400 = "interfaz.errores.solicitud_invalida"
handler403 = "interfaz.errores.acceso_denegado"
handler404 = "interfaz.errores.no_encontrado"
handler500 = "interfaz.errores.error_interno"
