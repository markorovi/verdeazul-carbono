#!/usr/bin/env python3
"""Pruebas de los servicios de catálogo (O5) y de resolución de alertas (O8.Rs) contra la base dev.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_catalogo.py

Corre como app_rw (DATABASE_URL_APP) a través de Django, con el mismo patrón que
scripts/probar_servicios.py: cada prueba corre en una transacción que SIEMPRE se revierte y al final
se comparan los conteos con los iniciales. El actor de catálogo es un R3, que no tiene rol de
lectura de mediciones: así las pruebas de Cd15 ejercitan la política de propósito de la migración
mediciones 0010. Nunca imprime cadenas de conexión ni secretos.
"""

from __future__ import annotations

import sys
import uuid
from datetime import timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import probar_servicios as ps  # noqa: E402  (configura Django y la conexión de app_rw)

from django.db import connection  # noqa: E402

import probar_mediciones as pm  # noqa: E402
from catalogo import servicios as catalogo  # noqa: E402
from catalogo.models import Asignacion, Finca, Parcela, Propiedad  # noqa: E402
from mediciones import alertas, firma, servicios  # noqa: E402
from mediciones.models import Alerta, Certificado, Medicion  # noqa: E402
from mediciones.transaccion import hora_de_la_base  # noqa: E402

PASA = ps.PASA
condicion = ps.condicion
resultado = ps.resultado
JUSTIFICACION = "Revisado con el equipo de gerencia, sin hallazgos"
# Región de parcelas distinta de la de los demás scripts de prueba.
X0, Y0, LADO = 900000, 1100000, 100
TABLAS_CONTEO = ps.TABLAS_CONTEO + ["catalogo_propiedad"]


def cuadrado(indice: int, desplazamiento: int = 0) -> str:
    x = X0 + indice * 2 * LADO + desplazamiento
    return f"POLYGON(({x} {Y0}, {x + LADO} {Y0}, {x + LADO} {Y0 + LADO}, {x} {Y0 + LADO}, {x} {Y0}))"


class Datos(ps.Datos):
    """Datos de prueba; las cuentas pueden registrar quién las dio de alta (creado_por)."""

    def cuenta_creada_por(self, creador, *roles: str):
        """En la aplicación, creado_por lo escribe el alta de cuentas al insertar la cuenta."""
        usuario_id = uuid.uuid4()
        self.sql(
            "INSERT INTO usuarios_usuario (id, password, correo, nombre, activo, creado_en, creado_por_id)"
            " VALUES (%s, %s, %s, %s, true, now(), %s)",
            [usuario_id, ps.HASH_FICTICIO, f"c-{usuario_id.hex[:12]}@{ps.DOMINIO}", ps.NOMBRE_PRUEBA, creador.pk],
        )
        for rol in roles:
            self.dar_rol(usuario_id, rol)
        return ps.Usuario.objects.get(pk=usuario_id)

    def finca(self, *propietarios) -> dict:
        """Finca activa con propietarios R6, dada de alta por un R3."""
        ctx = {"r3": self.usuario("R3"), "r7": self.usuario("R7"), "r7b": self.usuario("R7")}
        ctx["propietarios"] = list(propietarios) or [self.usuario("R6")]
        ctx["finca"] = catalogo.crear_finca(ctx["r3"], "Finca de prueba", [p.pk for p in ctx["propietarios"]]).finca_id
        return ctx

    def parcela(self, ctx, indice: int = 0) -> uuid.UUID:
        return catalogo.crear_parcela(ctx["r3"], ctx["finca"], f"P-{indice}", cuadrado(indice)).parcela_id

    def con_medicion(self, ctx, hasta: str) -> dict:
        """Parcela con técnico asignado y una medición llevada hasta borrador, presentada o certificada."""
        ctx["parcela"] = self.parcela(ctx)
        ctx["tecnico"], ctx["r2"] = self.usuario("R1"), self.usuario("R2")
        catalogo.asignar_tecnico(ctx["r3"], ctx["parcela"], ctx["tecnico"].pk, hora_de_la_base() + timedelta(days=30))
        ctx["periodo"] = servicios.abrir_periodo(ctx["r7"], ps.INICIO, ps.FIN).periodo_id
        registro = servicios.registrar_medicion(
            ctx["tecnico"], ctx["parcela"], ctx["periodo"], co2e_toneladas=ps.CO2E_BAJO, fecha_muestreo=ps.FECHA
        )
        ctx["medicion"] = registro.medicion_id
        if hasta in ("presentada", "certificada"):
            servicios.presentar_medicion(ctx["tecnico"], ctx["medicion"])
        if hasta == "certificada":
            servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
            ctx["certificado"] = servicios.aprobar_medicion(
                ctx["r2"], ctx["medicion"], huella_revisada=registro.huella
            ).certificado_id
        return ctx

    def avisos(self, tipo: str, **filtros) -> list[Alerta]:
        return list(Alerta.objects.filter(tipo=tipo, **filtros).order_by("creada_en", "id"))


# --------------------------------------------------------------------------- fincas


def c01():
    d = Datos()
    p1, p2 = d.usuario("R6"), d.usuario("R6")
    ctx = d.finca(p1, p2)
    propietarios = set(Propiedad.objects.filter(finca_id=ctx["finca"], hasta__isnull=True).values_list("dueno_id", flat=True))
    avisos = d.avisos(alertas.TIPO_ALTA_FINCA, detalle__finca_id=str(ctx["finca"]))
    ok = (propietarios == {p1.pk, p2.pk} and {a.cuenta_afectada_id for a in avisos} == {p1.pk, p2.pk}
          and all(a.usuario_id == ctx["r3"].pk and a.prioridad == "aviso" for a in avisos))
    return resultado(ok, f"propietarios={len(propietarios)}, avisos={len(avisos)} ({avisos[0].prioridad if avisos else '-'})")


def c02():
    d = Datos()
    actor = d.usuario("R3")
    otro = d.usuario("R6")
    obtenido = condicion(lambda: catalogo.crear_finca(actor, "Finca", [otro.pk, actor.pk]))
    return resultado(obtenido == "Cd14", obtenido)


def c03():
    d = Datos()
    actor, sin_r6 = d.usuario("R3"), d.usuario("R1")
    obtenido = condicion(lambda: catalogo.crear_finca(actor, "Finca", [sin_r6.pk]))
    return resultado(obtenido == "Cd14", obtenido)


def c04():
    d = Datos()
    actor, dueno = d.usuario("R3"), d.usuario("R6")
    antes = Finca.objects.count()
    with mock.patch.object(alertas, "registrar_aviso", side_effect=RuntimeError("aviso no registrado")):
        obtenido = condicion(lambda: catalogo.crear_finca(actor, "Finca sin aviso", [dueno.pk]))
    despues = Finca.objects.count()
    propiedades = Propiedad.objects.filter(dueno_id=dueno.pk).count()
    return resultado(obtenido == "excepción RuntimeError" and antes == despues and propiedades == 0,
                     f"{obtenido}; fincas {antes} y {despues}; propiedades del dueño {propiedades}")


# --------------------------------------------------------------------------- parcelas


def c05():
    d = Datos()
    ctx = d.finca()
    r = catalogo.crear_parcela(ctx["r3"], ctx["finca"], "P-1", cuadrado(0))
    avisos = d.avisos(alertas.TIPO_ALTA_PARCELA, parcela_id=r.parcela_id)
    ok = r.dada_de_baja_en is None and r.avisos == 1 and len(avisos) == 1 and avisos[0].cuenta_afectada_id == ctx["propietarios"][0].pk
    return resultado(ok, f"parcela activa, avisos={len(avisos)}")


def c06():
    d = Datos()
    ctx = d.finca()
    d.parcela(ctx, 0)
    obtenido = condicion(lambda: catalogo.crear_parcela(ctx["r3"], ctx["finca"], "P-2", cuadrado(0, 50)))
    borde = condicion(lambda: catalogo.crear_parcela(ctx["r3"], ctx["finca"], "P-3", cuadrado(0, ps.LADO)))
    return resultado(obtenido == "UNIDAD" and borde == PASA, f"traslape {obtenido}; borde compartido {borde}")


def c07():
    d = Datos()
    ctx = d.finca()
    dueno = ctx["propietarios"][0]
    obtenido = condicion(lambda: catalogo.crear_parcela(dueno, ctx["finca"], "P-1", cuadrado(0)))
    return resultado(obtenido == "Cd14", obtenido)


# --------------------------------------------------------------------------- propietarios


def c08():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "certificada")
    d.actor(ctx["r7"])
    antes = Certificado.objects.get(pk=ctx["certificado"])
    anterior, nuevo = ctx["propietarios"][0], d.usuario("R6")
    r = catalogo.cambiar_propietarios(ctx["r3"], ctx["finca"], agregar=[nuevo.pk], retirar=[anterior.pk])
    d.actor(ctx["r7"])
    despues = Certificado.objects.get(pk=ctx["certificado"])
    historial = dict(Propiedad.objects.filter(finca_id=ctx["finca"]).values_list("dueno_id", "hasta"))
    sin_cambio = (antes.payload, antes.firma, antes.estado) == (despues.payload, despues.firma, despues.estado)
    valida = firma.verificar(ps.documento(despues), firma.huella_publica()).estado == firma.ESTADO_VALIDO
    ok = (r.propietarios == 1 and sin_cambio and valida and historial[anterior.pk] is not None
          and historial[nuevo.pk] is None)
    return resultado(ok, f"pasa; certificado sin cambios={sin_cambio}, firma válida={valida}, "
                         f"titular anterior con fecha de fin={historial[anterior.pk] is not None}")


def c09():
    d = Datos()
    ctx = d.finca()
    obtenido = condicion(lambda: catalogo.cambiar_propietarios(ctx["r3"], ctx["finca"], agregar=[ctx["r3"].pk]))
    return resultado(obtenido == "Cd14", obtenido)


def c10():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "borrador")
    nuevo = d.usuario("R6")
    obtenido = condicion(lambda: catalogo.cambiar_propietarios(ctx["r3"], ctx["finca"], agregar=[nuevo.pk]))
    return resultado(obtenido == "Cd15", f"{obtenido} (actor R3, sin rol de lectura de mediciones)")


def c11():
    d = Datos()
    ctx = d.finca()
    propio = d.cuenta_creada_por(ctx["r3"], "R6")
    ajeno = d.usuario("R6")
    catalogo.cambiar_propietarios(ctx["r3"], ctx["finca"], agregar=[propio.pk, ajeno.pk])
    prioridades = {a.cuenta_afectada_id: a.prioridad for a in d.avisos(alertas.TIPO_CAMBIO_PROPIETARIOS)
                   if a.detalle.get("finca_id") == str(ctx["finca"])}
    ok = prioridades == {propio.pk: "prioritaria", ajeno.pk: "aviso"}
    return resultado(ok, f"dada de alta por el actor {prioridades.get(propio.pk)}; otra {prioridades.get(ajeno.pk)}")


def c12():
    d = Datos()
    ctx = d.finca()
    ultimo = ctx["propietarios"][0]
    obtenido = condicion(lambda: catalogo.cambiar_propietarios(ctx["r3"], ctx["finca"], retirar=[ultimo.pk]))
    return resultado(obtenido == "PROPIEDAD", obtenido)


# --------------------------------------------------------------------------- modificar parcela


def c13():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    r = catalogo.modificar_parcela(ctx["r3"], parcela, codigo="P-renombrada", wkt=cuadrado(5))
    distinto = catalogo.geometria.limites_distintos(parcela, cuadrado(5))
    return resultado(r.codigo == "P-renombrada" and not distinto, f"código {r.codigo}; límites nuevos aplicados={not distinto}")


def c14():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "certificada")
    limites = condicion(lambda: catalogo.modificar_parcela(ctx["r3"], ctx["parcela"], wkt=cuadrado(5)))
    datos = condicion(lambda: catalogo.modificar_parcela(ctx["r3"], ctx["parcela"], codigo="P-nuevo"))
    return resultado(limites == "Cd15" and datos == PASA, f"límites {limites}; solo datos {datos}")


def c15():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "presentada")
    obtenido = condicion(lambda: catalogo.modificar_parcela(ctx["r3"], ctx["parcela"], codigo="P-nuevo"))
    return resultado(obtenido == "Cd15", obtenido)


def c16():
    d = Datos()
    ctx = d.finca()
    d.parcela(ctx, 0)
    otra = d.parcela(ctx, 1)
    obtenido = condicion(lambda: catalogo.modificar_parcela(ctx["r3"], otra, wkt=cuadrado(0, 30)))
    return resultado(obtenido == "UNIDAD", obtenido)


# --------------------------------------------------------------------------- asignación de técnicos


def c17():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    tecnico = d.usuario("R1")
    r = catalogo.asignar_tecnico(ctx["r3"], parcela, tecnico.pk, hora_de_la_base() + timedelta(days=7))
    avisos = d.avisos(alertas.TIPO_ASIGNACION_TECNICO, parcela_id=parcela)
    vigente = Asignacion.objects.filter(pk=r.asignacion_id, hasta__gt=hora_de_la_base()).exists()
    ok = vigente and len(avisos) == 1 and avisos[0].cuenta_afectada_id == tecnico.pk and r.prioridad == "aviso"
    return resultado(ok, f"asignación vigente={vigente}, avisos={len(avisos)} ({r.prioridad})")


def c18():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    tecnico = d.usuario("R1", "R3")
    obtenido = condicion(lambda: catalogo.asignar_tecnico(tecnico, parcela, tecnico.pk, hora_de_la_base() + timedelta(days=7)))
    return resultado(obtenido == "Cd14", obtenido)


def c19():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    sin_r1 = d.usuario("R2")
    obtenido = condicion(lambda: catalogo.asignar_tecnico(ctx["r3"], parcela, sin_r1.pk, hora_de_la_base() + timedelta(days=7)))
    return resultado(obtenido == "Cd14", obtenido)


def c20():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    tecnico = d.usuario("R1")
    obtenido = condicion(lambda: catalogo.asignar_tecnico(ctx["r3"], parcela, tecnico.pk, hora_de_la_base() - timedelta(hours=1)))
    return resultado(obtenido == "Cd14", obtenido)


def c21():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    tecnico = d.cuenta_creada_por(ctx["r3"], "R1")
    r = catalogo.asignar_tecnico(ctx["r3"], parcela, tecnico.pk, hora_de_la_base() + timedelta(days=7))
    return resultado(r.prioridad == "prioritaria", f"técnico dado de alta por el actor: {r.prioridad}")


# --------------------------------------------------------------------------- bajas


def c22():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    r = catalogo.dar_de_baja_parcela(ctx["r3"], parcela)
    sigue = Parcela.objects.filter(pk=parcela).exists()
    return resultado(r.dada_de_baja_en is not None and sigue, f"baja lógica={r.dada_de_baja_en is not None}, fila conservada={sigue}")


def c23():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "borrador")
    obtenido = condicion(lambda: catalogo.dar_de_baja_parcela(ctx["r3"], ctx["parcela"]))
    return resultado(obtenido == "Cd15", obtenido)


def c24():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "certificada")
    obtenido = condicion(lambda: catalogo.dar_de_baja_parcela(ctx["r3"], ctx["parcela"]))
    return resultado(obtenido == "Cd15", obtenido)


def c25():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    nombres = [n for n in dir(catalogo) if any(p in n.lower() for p in ("borrar", "eliminar", "delete", "suprimir"))]

    def borrar():
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM catalogo_parcela WHERE id = %s", [parcela])

    obtenido = condicion(borrar)
    return resultado(not nombres and obtenido == "falla 42501", f"servicios de borrado={len(nombres)}; DELETE directo {obtenido}")


def c26():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "certificada")
    d.actor(ctx["r3"])
    sin_proposito = Medicion.objects.filter(pk=ctx["medicion"]).count()
    certificados = Certificado.objects.filter(pk=ctx["certificado"]).count()
    d.sql("SELECT set_config('app.proposito', 'catalogo', true)")
    con_proposito = Medicion.objects.filter(pk=ctx["medicion"]).count()
    certificados_con_proposito = Certificado.objects.filter(pk=ctx["certificado"]).count()
    d.sql("SELECT set_config('app.proposito', '', true)")
    ok = (sin_proposito, certificados, con_proposito, certificados_con_proposito) == (0, 0, 1, 0)
    return resultado(ok, f"R3 sin propósito {sin_proposito}; con propósito {con_proposito}; certificados {certificados_con_proposito}")


# --------------------------------------------------------------------------- alertas


def alerta_de_finca(d: Datos) -> tuple[dict, Alerta]:
    ctx = d.finca()
    return ctx, d.avisos(alertas.TIPO_ALTA_FINCA, detalle__finca_id=str(ctx["finca"]))[0]


def c27():
    d = Datos()
    ctx, alerta = alerta_de_finca(d)
    r = alertas.resolver_alerta(ctx["r7"], alerta.pk, justificacion=JUSTIFICACION)
    guardada = Alerta.objects.get(pk=alerta.pk)
    ok = guardada.resuelta_por_id == ctx["r7"].pk and guardada.justificacion_resolucion == JUSTIFICACION and r.resuelta_en is not None
    return resultado(ok, f"resuelta, justificación guardada={guardada.justificacion_resolucion == JUSTIFICACION}")


def c28():
    d = Datos()
    ctx, alerta = alerta_de_finca(d)
    afectado = ctx["propietarios"][0]
    origen = condicion(lambda: alertas.resolver_alerta(ctx["r3"], alerta.pk, justificacion=JUSTIFICACION))
    cuenta = condicion(lambda: alertas.resolver_alerta(afectado, alerta.pk, justificacion=JUSTIFICACION))
    return resultado(origen == cuenta == "Cd18", f"quien la originó {origen}; cuenta afectada {cuenta}")


def c29():
    d = Datos()
    ctx = d.con_medicion(d.finca(), "certificada")
    servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=ps.JUSTIFICACION)
    aviso = d.avisos(alertas.TIPO_ANULACION_CERTIFICADO, medicion_id=ctx["medicion"])[0]
    propio = condicion(lambda: alertas.resolver_alerta(ctx["r7"], aviso.pk, justificacion=JUSTIFICACION))
    otro = condicion(lambda: alertas.resolver_alerta(ctx["r7b"], aviso.pk, justificacion=JUSTIFICACION))
    return resultado(propio == "Cd18" and otro == PASA, f"R7 que anuló {propio}; otro R7 {otro}")


def c30():
    d = Datos()
    ctx, alerta = alerta_de_finca(d)
    obtenido = condicion(lambda: alertas.resolver_alerta(ctx["r7"], alerta.pk, justificacion="  corta  "))
    return resultado(obtenido == "Cd18", obtenido)


def c31():
    d = Datos()
    ctx, alerta = alerta_de_finca(d)
    alertas.resolver_alerta(ctx["r7"], alerta.pk, justificacion=JUSTIFICACION)
    obtenido = condicion(lambda: alertas.resolver_alerta(ctx["r7b"], alerta.pk, justificacion=JUSTIFICACION))
    return resultado(obtenido == "Cd18", obtenido)


def c32():
    d = Datos()
    ctx, alerta = alerta_de_finca(d)
    sentencia = "UPDATE mediciones_alerta SET resuelta_en = now(), resuelta_por_id = %s, justificacion_resolucion = %s WHERE id = %s"
    origen = condicion(lambda: d.afectar(sentencia, [ctx["r3"].pk, JUSTIFICACION, alerta.pk]))
    afectada = condicion(lambda: d.afectar(sentencia, [ctx["propietarios"][0].pk, JUSTIFICACION, alerta.pk]))
    return resultado(origen == afectada == "falla 23514", f"quien la originó {origen}; cuenta afectada {afectada}")


# --------------------------------------------------------------------------- ejecución

PRUEBAS = [
    ("C01", "Crear finca con dos propietarios R6", "pasa, un aviso por propietario", c01),
    ("C02", "Crear finca con el actor como propietario (caso 69)", "Cd14", c02),
    ("C03", "Crear finca con propietario sin R6", "Cd14", c03),
    ("C04", "Crear finca con el aviso forzado a fallar", "no se crea", c04),
    ("C05", "Crear parcela", "pasa, aviso a R7", c05),
    ("C06", "Crear parcela traslapada; borde compartido", "UNIDAD; pasa", c06),
    ("C07", "Crear parcela siendo propietario de la finca", "Cd14", c07),
    ("C08", "Cambiar solo propietarios con certificado vigente (caso 47)", "pasa, certificado sin cambios", c08),
    ("C09", "Agregarse a sí mismo como propietario", "Cd14", c09),
    ("C10", "Cambiar propietarios con medición en curso", "Cd15", c10),
    ("C11", "Prioridad del aviso según quién dio de alta la cuenta", "prioritaria y aviso", c11),
    ("C12", "Retirar al único propietario", "PROPIEDAD", c12),
    ("C13", "Modificar parcela sin mediciones ni certificados", "pasa", c13),
    ("C14", "Modificar límites con certificado vigente (caso 48)", "Cd15; datos pasa", c14),
    ("C15", "Modificar datos con medición en curso", "Cd15", c15),
    ("C16", "Modificar límites hacia un traslape", "UNIDAD", c16),
    ("C17", "Asignar técnico con vencimiento (caso 45)", "pasa, aviso", c17),
    ("C18", "Autoasignación (caso 46)", "Cd14", c18),
    ("C19", "Asignar a una cuenta sin R1", "Cd14", c19),
    ("C20", "Asignar con vencimiento pasado", "Cd14", c20),
    ("C21", "Asignar un técnico dado de alta por el actor", "prioritaria", c21),
    ("C22", "Dar de baja una parcela", "baja lógica", c22),
    ("C23", "Dar de baja con medición en curso (caso 49)", "Cd15", c23),
    ("C24", "Dar de baja con certificado vigente", "Cd15", c24),
    ("C25", "No hay borrado físico", "sin servicio; DELETE 42501", c25),
    ("C26", "R3 ve el estado de mediciones solo con propósito catálogo", "0; 1; certificados 0", c26),
    ("C27", "Resolver alerta por un R7 que no es parte", "pasa", c27),
    ("C28", "Resolver alerta siendo parte (caso 57)", "Cd18, Cd18", c28),
    ("C29", "Alerta de anulación resuelta por el R7 que anuló", "Cd18; otro R7 pasa", c29),
    ("C30", "Resolver con justificación corta", "Cd18", c30),
    ("C31", "Resolver una alerta ya resuelta", "Cd18", c31),
    ("C32", "La base rechaza que resuelva una parte de la alerta", "23514, 23514", c32),
]


def conteos() -> dict[str, int]:
    original = ps.TABLAS_CONTEO
    ps.TABLAS_CONTEO = TABLAS_CONTEO
    try:
        return ps.conteos()
    finally:
        ps.TABLAS_CONTEO = original


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    try:
        ps.usar(ps.APP)
        iniciales = conteos()
        resultados = [ps.ejecutar(*prueba) for prueba in PRUEBAS]
        finales = conteos()
    except ps.DatabaseError as error:
        raise SystemExit(f"[FALLO] Error de base de datos {ps._sqlstate(error)}") from None
    finally:
        ps.connections["default"].close()
    pm.imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    print(f"\nTotal: {correctas}/{len(resultados)} OK")
    limpio = finales == iniciales
    print(f"Conteos antes: {iniciales}")
    print(f"Conteos después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio else 1


if __name__ == "__main__":
    sys.exit(main())
