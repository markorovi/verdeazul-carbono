from django.urls import path

from usuarios import views

urlpatterns = [
    path("acceso/", views.acceso, name="acceso"),
    path("acceso/segundo-factor/", views.segundo_factor, name="segundo_factor"),
    path("salida/", views.salida, name="salida"),
    path("cuenta/", views.cuenta, name="cuenta"),
]
