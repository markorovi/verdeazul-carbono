from django.urls import path

from mediciones import views

urlpatterns = [
    path("certificados/clave-publica/", views.clave_publica, name="clave_publica"),
    path("verificar/", views.verificar, name="verificar"),
    path("api/verificar/", views.verificar_api, name="verificar_api"),
]
