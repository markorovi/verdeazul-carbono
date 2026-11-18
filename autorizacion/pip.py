"""PIP: reúne desde la base los hechos que necesita la política, con el actor declarado.

Corre dentro de la transacción del PEP, con app.usuario_id del sujeto: la RLS limita lo que ve, y
un objeto que el sujeto no puede ver produce hechos falsos (falla cerrado). Solo calcula los hechos
de las condiciones de política que exigen los permisos candidatos del sujeto. La salida no lleva
datos personales: solo banderas y contadores.

Región (Cd22): el modelo no registra regiones. Se toma como región del técnico el conjunto de
fincas donde tiene una asignación vigente; una parcela es de su región si pertenece a una de ellas.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone

from django.db import connection, transaction

from autorizacion import motor
from catalogo.models import Asignacion, Parcela, Propiedad
from mediciones import plazos
from mediciones.models import Certificado, Enmienda, Medicion, PoliticaParametro

CLAVE_VENTANA_CORTA = "wc_horas"
CLAVE_VENTANA_LARGA = "wl_dias"
TIPOS_CON_PARCELA = ("parcela", "medicion", "certificado", "enmienda")


@dataclass(frozen=True)
class Objeto:
    """Objeto de la operación: tipo (parcela, medicion, certificado, enmienda, periodo, finca,
    cuenta, alerta, ventana, acceso o ninguno) e identificador."""

    tipo: str = "ninguno"
    id: object = None


@dataclass(frozen=True)
class Hechos:
    hechos: dict
    parcela_id: uuid.UUID | None = None
    ajena: bool = True
    detalle: dict = field(default_factory=dict)


@dataclass(frozen=True)
class _Contexto:
    parcela_id: uuid.UUID | None
    finca_id: uuid.UUID | None
    estado_medicion: str | None
    # Fecha del objeto para Cd2: un instante (emisión) o un período (inicio, fin).
    instante: datetime | None
    periodo: tuple[datetime, datetime] | None


def condiciones_necesarias(operacion: str, roles) -> list[str]:
    """Condiciones de política de los permisos que el sujeto podría usar, sin repetir y en orden."""
    permisos = motor.matriz()["operaciones"].get(operacion) or {}
    de_politica = set(motor.matriz()["condiciones_politica"])
    vistas: list[str] = []
    for rol in roles:
        for condicion in permisos.get(rol, []):
            if condicion in de_politica and condicion not in vistas:
                vistas.append(condicion)
    return vistas


def parametros_politica() -> dict:
    """Umbrales de H2 de PoliticaParametro. Si falta alguno, la política deniega Cd9."""
    filas = PoliticaParametro.objects.filter(clave__in=motor.PARAMETROS_H2).values_list("clave", "valor")
    return {clave: int(valor) for clave, valor in filas}


def _dia(fecha) -> datetime:
    return datetime.combine(fecha, time.min, tzinfo=timezone.utc)


def _contexto(objeto: Objeto) -> _Contexto:
    vacio = _Contexto(None, None, None, None, None)
    if objeto.tipo == "parcela":
        finca = Parcela.objects.filter(pk=objeto.id).values_list("finca_id", flat=True).first()
        return _Contexto(objeto.id if finca else None, finca, None, None, None)
    if objeto.tipo == "medicion":
        fila = (
            Medicion.objects.filter(pk=objeto.id)
            .values_list("parcela_id", "parcela__finca_id", "estado", "periodo__inicio", "periodo__fin")
            .first()
        )
        if fila is None:
            return vacio
        return _Contexto(fila[0], fila[1], fila[2], None, (_dia(fila[3]), _dia(fila[4]) + timedelta(days=1)))
    if objeto.tipo == "certificado":
        fila = (
            Certificado.objects.filter(pk=objeto.id)
            .values_list("parcela_id", "parcela__finca_id", "emitido_en")
            .first()
        )
        return vacio if fila is None else _Contexto(fila[0], fila[1], None, fila[2], None)
    if objeto.tipo == "enmienda":
        medicion = Enmienda.objects.filter(pk=objeto.id).values_list("medicion_id", flat=True).first()
        return vacio if medicion is None else _contexto(Objeto("medicion", medicion))
    if objeto.tipo == "finca":
        return _Contexto(None, objeto.id, None, None, None)
    return vacio


def _escalar(sentencia: str, parametros=()):
    with connection.cursor() as cursor:
        cursor.execute(sentencia, list(parametros))
        return cursor.fetchone()[0]


def _propietario(sujeto_id, objeto: Objeto, contexto: _Contexto) -> bool:
    """Cd2 a la fecha del objeto: emisión del certificado o período de la medición."""
    if objeto.tipo == "periodo":
        return Propiedad.objects.filter(dueno_id=sujeto_id, hasta__isnull=True).exists()
    if contexto.finca_id is None:
        return False
    propiedades = Propiedad.objects.filter(dueno_id=sujeto_id, finca_id=contexto.finca_id)
    if contexto.instante is not None:
        momento = contexto.instante
        return propiedades.filter(desde__lte=momento).exclude(hasta__lte=momento).exists()
    if contexto.periodo is not None:
        inicio, fin = contexto.periodo
        return propiedades.filter(desde__lt=fin).exclude(hasta__lte=inicio).exists()
    return propiedades.filter(hasta__isnull=True).exists()


def _fincas_de_la_region(sujeto_id) -> set:
    ahora = _hora()
    return set(
        Asignacion.objects.filter(tecnico_id=sujeto_id, desde__lte=ahora, hasta__gt=ahora)
        .values_list("parcela__finca_id", flat=True)
    )


def _habitual(sujeto_id, roles, parcela_id) -> bool:
    """Vínculo habitual: R1, parcelas asignadas; R2, parcelas de mediciones que tiene asignadas."""
    if parcela_id is None:
        return False
    if "R1" in roles and _escalar("SELECT app_tecnico_asignado(%s)", [parcela_id]):
        return True
    return "R2" in roles and Medicion.objects.filter(parcela_id=parcela_id, verificador_asignado_id=sujeto_id).exists()


def _hora() -> datetime:
    return _escalar("SELECT now()")


def _momento_local() -> tuple[int, int]:
    """Día ISO (1 = lunes) y hora en la zona del horario laboral, con la hora de la base."""
    zona = motor.politica()["horario_laboral"]["zona"]
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT extract(isodow FROM now() AT TIME ZONE %s)::int, extract(hour FROM now() AT TIME ZONE %s)::int",
            [zona, zona],
        )
        return tuple(cursor.fetchone())


def es_laboral(dia_iso: int, hora: int, horario: dict | None = None) -> bool:
    horario = horario or motor.politica()["horario_laboral"]
    return dia_iso in horario["dias_iso"] and horario["desde_hora"] <= hora < horario["hasta_hora"]


def _contar_ajenas(sujeto_id, parcela_id) -> tuple[int, int]:
    """Parcelas ajenas distintas consultadas (concedidas) en la ventana corta y en la larga, sin la
    actual; quien llama suma la actual si es ajena."""
    horas = plazos.leer_parametro_entero(CLAVE_VENTANA_CORTA)
    dias = plazos.leer_parametro_entero(CLAVE_VENTANA_LARGA)
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(DISTINCT parcela_id) FILTER (WHERE sello > now() - make_interval(hours => %s)),"
            "       count(DISTINCT parcela_id) FILTER (WHERE sello > now() - make_interval(days => %s))"
            "  FROM autorizacion_registroacceso"
            " WHERE usuario_id = %s AND ajena AND resultado = 'concedido' AND parcela_id IS NOT NULL"
            "   AND parcela_id IS DISTINCT FROM %s",
            [horas, dias, sujeto_id, parcela_id],
        )
        corta, larga = cursor.fetchone()
    return corta, larga


def _h2(sujeto_id, roles, contexto: _Contexto) -> tuple[dict, bool]:
    ajena = not _habitual(sujeto_id, roles, contexto.parcela_id)
    try:
        with transaction.atomic():
            corta, larga = _contar_ajenas(sujeto_id, contexto.parcela_id)
            dia, hora = _momento_local()
    except Exception:
        # Falla degradada: la política concede solo el vínculo habitual y deniega toda exportación.
        return {"disponible": False, "ajena": ajena}, ajena
    actual = 1 if ajena else 0
    return {
        "disponible": True,
        "ajena": ajena,
        "wc": corta + actual,
        "wl": larga + actual,
        "laboral": es_laboral(dia, hora),
    }, ajena


def reunir(sesion, roles, operacion: str, objeto: Objeto, bitacora) -> Hechos:
    sujeto_id = sesion.usuario.pk
    necesarias = condiciones_necesarias(operacion, roles)
    contexto = _contexto(objeto) if objeto.tipo != "ninguno" else _Contexto(None, None, None, None, None)
    hechos: dict = {}
    if "Cd1" in necesarias:
        hechos["asignacion_vigente"] = bool(
            contexto.parcela_id and _escalar("SELECT app_tecnico_asignado(%s)", [contexto.parcela_id])
        )
    if "Cd2" in necesarias:
        hechos["propietario"] = _propietario(sujeto_id, objeto, contexto)
    if "Cd3" in necesarias:
        hechos["ventana_vigente"] = bool(_escalar("SELECT app_ventana_auditoria_vigente()"))
    if "Cd4" in necesarias:
        hechos["segundo_factor"] = sesion.con_segundo_factor()
    if "Cd16" in necesarias:
        hechos["proyeccion_disponible"] = True
    if "Cd17" in necesarias:
        try:
            hechos["bitacora_disponible"] = bitacora.disponible() is True
        except Exception:
            hechos["bitacora_disponible"] = False
    if "Cd21" in necesarias:
        hechos["estado_visible_r2"] = contexto.estado_medicion not in (None, Medicion.Estado.BORRADOR)
    if "Cd22" in necesarias:
        hechos["misma_region"] = contexto.finca_id is not None and contexto.finca_id in _fincas_de_la_region(sujeto_id)
    ajena = True
    if "Cd9" in necesarias or operacion == motor.OPERACION_EXPORTAR:
        hechos["h2"], ajena = _h2(sujeto_id, roles, contexto)
    return Hechos(hechos, contexto.parcela_id, ajena)
