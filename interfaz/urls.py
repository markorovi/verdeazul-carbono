"""Rutas de la interfaz. Las de escritura se generan desde el registro: una por operación y servicio,
con el identificador del objeto en la URL cuando la operación lo tiene."""

from django.urls import path

from interfaz import registro, vistas


def _rutas_de_operaciones():
    rutas = []
    for entrada in registro.ENTRADAS:
        nombre = f"op-{entrada.clave}"
        if entrada.clase == registro.ESCRITURA:
            vista = vistas.vista_de_escritura(entrada)
            sufijo = "<uuid:objeto_id>/" if entrada.con_objeto else ""
            rutas.append(path(f"operaciones/{entrada.clave}/{sufijo}", vista, name=nombre))
        elif entrada.clase == registro.DENEGADA:
            rutas.append(path(f"operaciones/{entrada.clave}/", vistas.vista_denegada_a_todos(entrada), name=nombre))
    return rutas


urlpatterns = [
    path("", vistas.inicio, name="inicio"),
    path("salud/", vistas.salud, name="salud"),
    path("estaticos/<path:nombre>", vistas.estatico, name="estatico"),
    path("operaciones/", vistas.consola, name="consola"),
    path("operaciones/ir/", vistas.ir_a_operacion, name="ir_a_operacion"),
    *_rutas_de_operaciones(),
    path("mediciones/", vistas.lista_mediciones, name="lista_mediciones"),
    path("mediciones/<uuid:objeto_id>/", vistas.detalle_medicion, name="detalle_medicion"),
    path("periodos/", vistas.lista_periodos, name="lista_periodos"),
    path("periodos/<uuid:objeto_id>/", vistas.detalle_periodo, name="detalle_periodo"),
    path("certificados/", vistas.lista_certificados, name="lista_certificados"),
    path("certificados/<uuid:objeto_id>/", vistas.detalle_certificado, name="detalle_certificado"),
    path("enmiendas/", vistas.lista_enmiendas, name="lista_enmiendas"),
    path("enmiendas/<uuid:objeto_id>/", vistas.detalle_enmienda, name="detalle_enmienda"),
    path("catalogo/parcelas/", vistas.lista_parcelas, name="lista_parcelas"),
    path("catalogo/parcelas/<uuid:objeto_id>/", vistas.detalle_parcela, name="detalle_parcela"),
    path("catalogo/fincas/<uuid:objeto_id>/", vistas.detalle_finca, name="detalle_finca"),
    path("cuentas/", vistas.lista_cuentas, name="lista_cuentas"),
    path("cuentas/<uuid:objeto_id>/", vistas.detalle_cuenta, name="detalle_cuenta"),
    path("alertas/", vistas.lista_alertas, name="lista_alertas"),
    path("alertas/<uuid:objeto_id>/", vistas.detalle_alerta, name="detalle_alerta"),
    path("bitacora/", vistas.bitacora, name="bitacora"),
]
