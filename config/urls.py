from django.db import connection
from django.http import JsonResponse
from django.urls import include, path


def inicio(request):
    # Comprueba la conexión sin revelar la versión del servidor de base de datos.
    with connection.cursor() as cursor:
        cursor.execute("select 1")
        cursor.fetchone()
    return JsonResponse({"estado": "ok", "base_de_datos": "conectada"})


urlpatterns = [
    path("", inicio),
    path("", include("usuarios.urls")),
]
