"""Aviso al titular de la cuenta en su siguiente inicio de sesión (A9).

Fuente: las tablas de usuarios (migración 0005 y anteriores), sin duplicarlas. Al iniciar sesión se
calculan los cambios ocurridos desde el acceso anterior (last_login previo): uso del perfil de
emergencia, uso de un código de recuperación, roles asignados o revocados y ventanas de auditoría
solicitadas o abiertas para la cuenta. Quedan en la sesión y la primera página que los muestra los
retira (se ven una sola vez). Como last_login avanza con cada inicio, el siguiente no los repite.
"""

from __future__ import annotations

from django.db.models import Q

from usuarios.models import AccesoEmergencia, CodigoUnUso, RolUsuario, VentanaAuditoria

CLAVE_SESION = "avisos_titular"


def _fecha(momento) -> str:
    return momento.strftime("%Y-%m-%d %H:%M UTC")


def desde(usuario_id, anterior) -> list[str]:
    """Textos fijos con fecha y código de rol; ningún dato de otras personas."""
    if anterior is None:
        return []
    avisos: list[str] = []
    for usado in AccesoEmergencia.objects.filter(beneficiario_id=usuario_id, usado_en__gt=anterior).values_list(
            "usado_en", flat=True):
        avisos.append(f"Se usó un perfil de emergencia de su cuenta el {_fecha(usado)}.")
    for usado in CodigoUnUso.objects.filter(
            usuario_id=usuario_id, proposito=CodigoUnUso.Proposito.RECUPERACION, usado_en__gt=anterior
    ).values_list("usado_en", flat=True):
        avisos.append(f"Se usó un código de recuperación de su cuenta el {_fecha(usado)}.")
    for rol, inicio, fin in RolUsuario.objects.filter(
            Q(desde__gt=anterior) | Q(hasta__gt=anterior), usuario_id=usuario_id
    ).values_list("rol_id", "desde", "hasta").order_by("desde"):
        if inicio > anterior:
            avisos.append(f"Se le asignó el rol {rol} el {_fecha(inicio)}.")
        if fin is not None and fin > anterior:
            avisos.append(f"Se le revocó el rol {rol} el {_fecha(fin)}.")
    for solicitada, abierta in VentanaAuditoria.objects.filter(
            Q(solicitada_en__gt=anterior) | Q(abierta_en__gt=anterior), auditor_id=usuario_id
    ).values_list("solicitada_en", "abierta_en"):
        if solicitada is not None and solicitada > anterior:
            avisos.append(f"Se solicitó una ventana de auditoría para su cuenta el {_fecha(solicitada)}.")
        if abierta is not None and abierta > anterior:
            avisos.append(f"Se abrió una ventana de auditoría para su cuenta el {_fecha(abierta)}.")
    return avisos


def guardar(request, avisos: list[str]) -> None:
    if avisos:
        request.session[CLAVE_SESION] = avisos
    else:
        request.session.pop(CLAVE_SESION, None)


def retirar(request) -> list[str]:
    avisos = request.session.pop(CLAVE_SESION, None)
    return [a for a in avisos if isinstance(a, str)] if isinstance(avisos, list) else []
