from django.db import connection
from django.http import JsonResponse
from django.urls import path


def inicio(request):
    with connection.cursor() as cursor:
        cursor.execute("select version()")
        version = cursor.fetchone()[0]
    return JsonResponse({"estado": "ok", "base_de_datos": version[:40]})


urlpatterns = [
    path("", inicio),
]
