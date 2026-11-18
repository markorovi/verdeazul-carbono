from django.urls import path

from mediciones import views

urlpatterns = [
    path("certificados/clave-publica/", views.clave_publica, name="clave_publica"),
    path("clave-publica/", views.clave_publica_pagina, name="clave_publica_pagina"),
    path("verificar/", views.verificar, name="verificar"),
]
