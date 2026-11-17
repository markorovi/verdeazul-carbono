#!/usr/bin/env python3
"""Pruebas de reglas H1 y H3, inmutabilidad y RLS de mediciones contra la base dev.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_mediciones.py

Corre como app_rw (DATABASE_URL_APP) y, para las pruebas de propietario y TRUNCATE, como
migrador (DATABASE_URL_MIGRADOR). Cada prueba corre en una transacción que SIEMPRE se revierte:
las tablas de mediciones no admiten borrado, así que nada se confirma. Al final compara los conteos
con los iniciales. Nunca imprime cadenas de conexión ni secretos.
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Callable

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mediciones.huella import calcular_huella  # noqa: E402

APP = "app_rw"
MIGRADOR = "migrador"
VARIABLES_CONEXION = {APP: "DATABASE_URL_APP", MIGRADOR: "DATABASE_URL_MIGRADOR"}
PATRON_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")

PASA = "pasa"
INTEGRIDAD = "falla 23000"
CHECK = "falla 23514"
UNICIDAD = "falla 23505"
SIN_PERMISO = "falla 42501"

DOMINIO = "mediciones-prueba.test"
HASH_FICTICIO = "!no-usable"
HUELLA_FALSA = "f" * 64
CO2E_BAJO = Decimal("100.000")
CO2E_ALTO = Decimal("600.000")
FECHA = date(2026, 1, 15)
NOTAS = "Muestreo de prueba"
JUSTIFICACION = "Error detectado en el muestreo original"
MOTIVO = "Corrección del valor de muestreo"
DIAS_FUERA_DE_PLAZO = 91
# Región de parcelas distinta de la de probar_bd.py.
X0, Y0, LADO = 500000, 1100000, 100

TABLAS_NUEVAS = [
    "mediciones_politicaparametro",
    "mediciones_medicion",
    "mediciones_medicionversion",
    "mediciones_aprobacion",
    "mediciones_enmienda",
    "mediciones_certificado",
    "mediciones_alerta",
]
TABLAS_RLS = TABLAS_NUEVAS[1:6]
PARAMETROS_ESPERADOS = {
    "valto_tco2e": Decimal("500"),
    "tenm_dias": Decimal("90"),
    "wc_horas": Decimal("24"),
    "wl_dias": Decimal("30"),
    "h2_wc_laboral_blando": Decimal("10"),
    "h2_wc_laboral_duro": Decimal("25"),
    "h2_wc_fuera_blando": Decimal("3"),
    "h2_wc_fuera_duro": Decimal("8"),
    "h2_wl_blando": Decimal("40"),
    "h2_wl_duro": Decimal("100"),
}


class SinEfecto(Exception):
    """La sentencia no afectó filas (por ejemplo, la RLS las filtró sin error)."""


def intento(cur: psycopg.Cursor, accion: Callable[[], object]) -> str:
    """Ejecuta la acción en un savepoint y devuelve "pasa", "falla <sqlstate>" o "sin efecto"."""
    cur.execute("SAVEPOINT intento")
    try:
        accion()
    except psycopg.Error as error:
        cur.execute("ROLLBACK TO SAVEPOINT intento")
        return f"falla {error.sqlstate}"
    except SinEfecto:
        cur.execute("ROLLBACK TO SAVEPOINT intento")
        return "sin efecto"
    cur.execute("RELEASE SAVEPOINT intento")
    return PASA


# --------------------------------------------------------------------------- escenario


class Escenario:
    """Crea datos de prueba con la conexión dada, dentro de la transacción de la prueba."""

    def __init__(self, cur: psycopg.Cursor):
        self.cur = cur
        self.parcelas = 0

    def sql(self, sentencia: str, parametros=None) -> psycopg.Cursor:
        return self.cur.execute(sentencia, parametros)

    def uno(self, sentencia: str, parametros=None):
        fila = self.sql(sentencia, parametros).fetchone()
        return fila[0] if fila else None

    def afectar(self, sentencia: str, parametros) -> None:
        if self.sql(sentencia, parametros).rowcount != 1:
            raise SinEfecto()

    def actor(self, usuario_id) -> None:
        self.sql("SELECT set_config('app.usuario_id', %s, true)", ("" if usuario_id is None else str(usuario_id),))

    # catálogo y usuarios

    def usuario(self, *roles: str) -> uuid.UUID:
        usuario_id = uuid.uuid4()
        self.sql(
            "INSERT INTO usuarios_usuario (id, password, correo, nombre, activo, creado_en)"
            " VALUES (%s, %s, %s, %s, true, now())",
            (usuario_id, HASH_FICTICIO, f"u-{usuario_id.hex[:12]}@{DOMINIO}", "Usuario de prueba"),
        )
        for rol in roles:
            self.dar_rol(usuario_id, rol)
        return usuario_id

    def dar_rol(self, usuario_id, rol: str) -> None:
        self.sql(
            "INSERT INTO usuarios_rolusuario (id, usuario_id, rol_id, desde) VALUES (%s, %s, %s, now())",
            (uuid.uuid4(), usuario_id, rol),
        )

    def terminar_rol(self, usuario_id, rol: str) -> None:
        self.afectar(
            "UPDATE usuarios_rolusuario SET hasta = now() WHERE usuario_id = %s AND rol_id = %s AND hasta IS NULL",
            (usuario_id, rol),
        )

    def cambiar_rol(self, usuario_id, anterior: str, nuevo: str) -> None:
        self.terminar_rol(usuario_id, anterior)
        self.dar_rol(usuario_id, nuevo)

    def finca(self) -> uuid.UUID:
        finca_id = uuid.uuid4()
        self.sql("INSERT INTO catalogo_finca (id, nombre, creada_en) VALUES (%s, %s, now())", (finca_id, "Finca de prueba"))
        return finca_id

    def parcela(self, finca_id) -> uuid.UUID:
        x = X0 + self.parcelas * 2 * LADO
        self.parcelas += 1
        wkt = f"POLYGON(({x} {Y0}, {x + LADO} {Y0}, {x + LADO} {Y0 + LADO}, {x} {Y0 + LADO}, {x} {Y0}))"
        parcela_id = uuid.uuid4()
        self.sql(
            "INSERT INTO catalogo_parcela (id, finca_id, codigo, geom) VALUES (%s, %s, %s, ST_GeomFromText(%s, 5367))",
            (parcela_id, finca_id, f"MP-{parcela_id.hex[:8]}", wkt),
        )
        return parcela_id

    def asignar(self, tecnico, parcela) -> None:
        self.sql(
            "INSERT INTO catalogo_asignacion (id, tecnico_id, parcela_id, desde, hasta)"
            " VALUES (%s, %s, %s, now() - interval '1 hour', now() + interval '30 days')",
            (uuid.uuid4(), tecnico, parcela),
        )

    def propiedad(self, dueno, finca) -> None:
        self.sql(
            "INSERT INTO catalogo_propiedad (id, dueno_id, finca_id, desde) VALUES (%s, %s, %s, now())",
            (uuid.uuid4(), dueno, finca),
        )

    def ventana(self, auditor, abierta_por, solicitada_por) -> None:
        self.sql(
            "INSERT INTO usuarios_ventanaauditoria (id, auditor_id, inicio, fin, abierta_por_id, solicitada_por_id)"
            " VALUES (%s, %s, now() - interval '1 hour', now() + interval '1 hour', %s, %s)",
            (uuid.uuid4(), auditor, abierta_por, solicitada_por),
        )

    def periodo(self, r7=None) -> uuid.UUID:
        """Abrir un período exige un actor R7 vigente; si no se indica, se crea uno."""
        self.actor(r7 or self.usuario("R7"))
        return self.insertar_periodo()

    def insertar_periodo(self) -> uuid.UUID:
        """Inserta un período con el actor ya declarado en la transacción."""
        periodo_id = uuid.uuid4()
        self.sql(
            "INSERT INTO mediciones_periodo (id, inicio, fin, estado) VALUES (%s, %s, %s, 'abierto')",
            (periodo_id, date(2099, 1, 1), date(2099, 12, 31)),
        )
        return periodo_id

    def cerrar(self, periodo, actor) -> None:
        """La base exige R7 y fija cerrado_en = now() y cerrado_por = actor."""
        self.actor(actor)
        self.afectar(
            "UPDATE mediciones_periodo SET estado = 'cerrado', cerrado_en = now(), cerrado_por_id = %s"
            " WHERE id = %s",
            (actor, periodo),
        )

    # mediciones

    def medicion(self, tecnico, parcela, periodo, registrada_por=None) -> uuid.UUID:
        self.actor(tecnico)
        medicion_id = uuid.uuid4()
        self.sql(
            "INSERT INTO mediciones_medicion (id, parcela_id, periodo_id, registrada_por_id, estado, ciclo, creada_en)"
            " VALUES (%s, %s, %s, %s, 'borrador', 1, now())",
            (medicion_id, parcela, periodo, registrada_por or tecnico),
        )
        return medicion_id

    def version(self, medicion, numero, creada_por, co2e=CO2E_BAJO, fecha=FECHA, notas=NOTAS,
                enmienda=None, actor=None) -> uuid.UUID:
        self.actor(actor or creada_por)
        version_id = uuid.uuid4()
        self.sql(
            "INSERT INTO mediciones_medicionversion (id, medicion_id, numero, co2e_toneladas, fecha_muestreo,"
            " notas, creada_por_id, creada_en, huella, huella_previa, enmienda_id)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, now(), %s, NULL, %s)",
            (version_id, medicion, numero, co2e, fecha, notas, creada_por, HUELLA_FALSA, enmienda),
        )
        return version_id

    def cambiar_estado(self, medicion, estado: str, actor, devuelta_por=None) -> None:
        self.actor(actor)
        if devuelta_por is None:
            self.afectar("UPDATE mediciones_medicion SET estado = %s WHERE id = %s", (estado, medicion))
        else:
            self.afectar(
                "UPDATE mediciones_medicion SET estado = %s, devuelta_por_id = %s WHERE id = %s",
                (estado, devuelta_por, medicion),
            )

    def estado(self, medicion, actor) -> tuple[str, int] | None:
        self.actor(actor)
        return self.sql("SELECT estado, ciclo FROM mediciones_medicion WHERE id = %s", (medicion,)).fetchone()

    def aprobar(self, medicion, version, aprobador, ciclo: int = 1) -> None:
        self.actor(aprobador)
        self.sql(
            "INSERT INTO mediciones_aprobacion (id, medicion_id, version_id, ciclo, aprobador_id, huella_aprobada, aprobada_en)"
            " VALUES (%s, %s, %s, %s, %s, %s, now())",
            (uuid.uuid4(), medicion, version, ciclo, aprobador, HUELLA_FALSA),
        )

    def emitir(self, ctx: dict, emisor, version=None) -> uuid.UUID:
        self.actor(emisor)
        ciclo = self.uno("SELECT ciclo FROM mediciones_medicion WHERE id = %s", (ctx["medicion"],))
        certificado_id = uuid.uuid4()
        self.sql(
            "INSERT INTO mediciones_certificado (id, parcela_id, periodo_id, medicion_id, version_id, ciclo, estado, emitido_en)"
            " VALUES (%s, %s, %s, %s, %s, %s, 'vigente', now())",
            (certificado_id, ctx["parcela"], ctx["periodo"], ctx["medicion"], version or ctx["version"], ciclo or 1),
        )
        return certificado_id

    def anular(self, certificado, anulador, justificacion=JUSTIFICACION) -> None:
        self.actor(anulador)
        self.afectar(
            "UPDATE mediciones_certificado SET estado = 'anulado', anulado_en = now(), anulado_por_id = %s,"
            " justificacion_anulacion = %s WHERE id = %s",
            (anulador, justificacion, certificado),
        )

    def enmienda(self, medicion, solicitante, co2e=Decimal("150.000"), fecha=date(2026, 2, 1),
                 notas="Muestreo corregido") -> uuid.UUID:
        self.actor(solicitante)
        enmienda_id = uuid.uuid4()
        self.sql(
            "INSERT INTO mediciones_enmienda (id, medicion_id, solicitante_id, motivo, co2e_nuevo, fecha_nueva,"
            " notas_nuevas, estado, solicitada_en) VALUES (%s, %s, %s, %s, %s, %s, %s, 'solicitada', now())",
            (enmienda_id, medicion, solicitante, MOTIVO, co2e, fecha, notas),
        )
        return enmienda_id

    def resolver(self, enmienda, autorizador, estado: str = "autorizada") -> None:
        self.actor(autorizador)
        self.afectar(
            "UPDATE mediciones_enmienda SET estado = %s, autorizador_id = %s, resuelta_en = now() WHERE id = %s",
            (estado, autorizador, enmienda),
        )

    # flujos

    def base(self, co2e=CO2E_BAJO) -> dict:
        """Técnico R1 asignado, R2, R7, parcela, período abierto, medición y versión 1 en borrador."""
        ctx = {"tecnico": self.usuario("R1"), "r2": self.usuario("R2"), "r7": self.usuario("R7")}
        ctx["finca"] = self.finca()
        ctx["parcela"] = self.parcela(ctx["finca"])
        self.asignar(ctx["tecnico"], ctx["parcela"])
        ctx["periodo"] = self.periodo(ctx["r7"])
        ctx["medicion"] = self.medicion(ctx["tecnico"], ctx["parcela"], ctx["periodo"])
        ctx["version"] = self.version(ctx["medicion"], 1, ctx["tecnico"], co2e=co2e)
        return ctx

    def presentada_y_cerrada(self, co2e=CO2E_BAJO) -> dict:
        ctx = self.base(co2e)
        self.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"])
        self.cerrar(ctx["periodo"], ctx["r7"])
        return ctx

    def aprobada(self, co2e=CO2E_BAJO) -> dict:
        ctx = self.presentada_y_cerrada(co2e)
        self.aprobar(ctx["medicion"], ctx["version"], ctx["r2"])
        return ctx

    def certificada(self, co2e=CO2E_BAJO) -> dict:
        ctx = self.aprobada(co2e)
        ctx["certificado"] = self.emitir(ctx, ctx["r2"])
        return ctx


# --------------------------------------------------------------------------- pruebas


def resultado(ok: bool, obtenido: str):
    return ok, obtenido


def p01(app, mig):
    filas = dict(app.execute("SELECT clave, valor FROM mediciones_politicaparametro").fetchall())
    ok = filas == PARAMETROS_ESPERADOS
    return resultado(ok, f"{len(filas)} parámetros, valores esperados={ok}")


def liberar(cur: psycopg.Cursor) -> None:
    """Revierte la transacción de esa conexión para que la otra pueda tomar locks exclusivos."""
    cur.connection.rollback()


def p02(app, mig):
    obtenidos = [
        intento(app, lambda: app.execute("UPDATE mediciones_politicaparametro SET valor = 1")),
        intento(app, lambda: app.execute("DELETE FROM mediciones_politicaparametro")),
        intento(app, lambda: app.execute("TRUNCATE mediciones_politicaparametro")),
    ]
    liberar(app)
    obtenidos += [
        intento(mig, lambda: mig.execute("UPDATE mediciones_politicaparametro SET valor = 1")),
        intento(mig, lambda: mig.execute("DELETE FROM mediciones_politicaparametro")),
        intento(mig, lambda: mig.execute("TRUNCATE mediciones_politicaparametro")),
    ]
    esperados = [SIN_PERMISO] * 3 + [INTEGRIDAD] * 3
    return resultado(obtenidos == esperados, "app_rw " + ", ".join(obtenidos[:3]) + "; migrador " + ", ".join(obtenidos[3:]))


ROLES_SIN_R7 = ("R1", "R2", "R3", "R4", "R5", "R6")


def intentos_por_rol(e: Escenario, accion: Callable[[], object]) -> dict[str, str]:
    """Ejecuta la acción con un actor por cada rol distinto de R7 y sin actor."""
    obtenidos = {}
    for rol in ROLES_SIN_R7:
        e.actor(e.usuario(rol))
        obtenidos[rol] = intento(e.cur, accion)
    e.actor(None)
    obtenidos["sin actor"] = intento(e.cur, accion)
    return obtenidos


def resumen_por_rol(obtenidos: dict[str, str]) -> str:
    return ", ".join(f"{rol} {valor}" for rol, valor in obtenidos.items())


def pe01(app, mig):
    e = Escenario(app)
    obtenidos = intentos_por_rol(e, e.insertar_periodo)
    return resultado(all(v == INTEGRIDAD for v in obtenidos.values()), resumen_por_rol(obtenidos))


def pe02(app, mig):
    e = Escenario(app)
    r7 = e.usuario("R7")
    obtenido = intento(app, lambda: e.periodo(r7))
    return resultado(obtenido == PASA, obtenido)


def cerrar_sin_fijar_actor(e: Escenario, periodo) -> None:
    e.afectar(
        "UPDATE mediciones_periodo SET estado = 'cerrado', cerrado_en = now() WHERE id = %s", (periodo,)
    )


def pe03(app, mig):
    e = Escenario(app)
    periodo = e.periodo()
    obtenidos = intentos_por_rol(e, lambda: cerrar_sin_fijar_actor(e, periodo))
    return resultado(all(v == INTEGRIDAD for v in obtenidos.values()), resumen_por_rol(obtenidos))


def pe04(app, mig):
    e = Escenario(app)
    r7, otro = e.usuario("R7"), e.usuario("R7")
    periodo = e.periodo(r7)
    e.actor(r7)
    obtenido = intento(app, lambda: e.afectar(
        "UPDATE mediciones_periodo SET estado = 'cerrado', cerrado_en = %s, cerrado_por_id = %s WHERE id = %s",
        (date(2000, 1, 1), otro, periodo)))
    fecha_ok, autor_ok = app.execute(
        "SELECT cerrado_en = now(), cerrado_por_id = %s FROM mediciones_periodo WHERE id = %s", (r7, periodo)
    ).fetchone()
    ok = obtenido == PASA and fecha_ok and autor_ok
    return resultado(ok, f"{obtenido}; cerrado_en = now(): {fecha_ok}; cerrado_por = actor: {autor_ok}")


def pe05(app, mig):
    e = Escenario(app)
    r7 = e.usuario("R7")
    periodo = e.periodo(r7)
    e.cerrar(periodo, r7)
    obtenido = intento(app, lambda: e.afectar(
        "UPDATE mediciones_periodo SET estado = 'abierto', cerrado_en = NULL, cerrado_por_id = NULL WHERE id = %s",
        (periodo,)))
    return resultado(obtenido == INTEGRIDAD, f"{obtenido} (reabrir como R7)")


def m01(app, mig):
    e = Escenario(app)
    tecnico = e.usuario("R1")
    parcela = e.parcela(e.finca())
    e.asignar(tecnico, parcela)
    periodo = e.periodo()
    obtenido = intento(app, lambda: e.medicion(tecnico, parcela, periodo))
    return resultado(obtenido == PASA, obtenido)


def m02(app, mig):
    e = Escenario(app)
    tecnico = e.usuario("R1")
    parcela = e.parcela(e.finca())
    periodo = e.periodo()
    obtenido = intento(app, lambda: e.medicion(tecnico, parcela, periodo))
    return resultado(obtenido == SIN_PERMISO, obtenido)


def m03(app, mig):
    e = Escenario(app)
    tecnico, r7 = e.usuario("R1"), e.usuario("R7")
    parcela = e.parcela(e.finca())
    e.asignar(tecnico, parcela)
    periodo = e.periodo()
    e.cerrar(periodo, r7)
    obtenido = intento(app, lambda: e.medicion(tecnico, parcela, periodo))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def m04(app, mig):
    e = Escenario(app)
    tecnico, otro = e.usuario("R1"), e.usuario("R1")
    parcela = e.parcela(e.finca())
    e.asignar(tecnico, parcela)
    e.asignar(otro, parcela)
    periodo = e.periodo()
    obtenido = intento(app, lambda: e.medicion(tecnico, parcela, periodo, registrada_por=otro))
    return resultado(obtenido == SIN_PERMISO, obtenido)


def m05(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.actor(None)
    visibles = e.uno("SELECT count(*) FROM mediciones_medicion WHERE id = %s", (ctx["medicion"],))
    parcela = e.parcela(ctx["finca"])
    e.asignar(ctx["tecnico"], parcela)

    def insertar_sin_actor():
        e.actor(None)
        app.execute(
            "INSERT INTO mediciones_medicion (id, parcela_id, periodo_id, registrada_por_id, estado, ciclo, creada_en)"
            " VALUES (%s, %s, %s, %s, 'borrador', 1, now())",
            (uuid.uuid4(), parcela, ctx["periodo"], ctx["tecnico"]),
        )

    insercion = intento(app, insertar_sin_actor)
    return resultado(visibles == 0 and insercion == SIN_PERMISO, f"filas visibles={visibles}, inserción {insercion}")


def m06(app, mig):
    e = Escenario(app)
    ctx = e.base()
    otra = e.parcela(ctx["finca"])
    otro_periodo = e.periodo()
    e.actor(ctx["tecnico"])
    parcela = intento(app, lambda: app.execute("UPDATE mediciones_medicion SET parcela_id = %s WHERE id = %s", (otra, ctx["medicion"])))
    periodo = intento(app, lambda: app.execute("UPDATE mediciones_medicion SET periodo_id = %s WHERE id = %s", (otro_periodo, ctx["medicion"])))
    return resultado(parcela == SIN_PERMISO and periodo == SIN_PERMISO, f"parcela {parcela}, período {periodo}")


def leer_version(e: Escenario, version) -> tuple:
    return e.sql(
        "SELECT medicion_id, numero, co2e_toneladas, fecha_muestreo, notas, creada_por_id, huella, huella_previa"
        " FROM mediciones_medicionversion WHERE id = %s",
        (version,),
    ).fetchone()


def huella_esperada(fila: tuple) -> str:
    medicion, numero, co2e, fecha, notas, creada_por, _, previa = fila
    return calcular_huella(medicion, numero, co2e, fecha, notas, creada_por, previa)


def v01(app, mig):
    e = Escenario(app)
    ctx = e.base(co2e=Decimal("123.4"))
    fila = leer_version(e, ctx["version"])
    coincide = fila[6] == huella_esperada(fila)
    ignorada = fila[6] != HUELLA_FALSA
    return resultado(coincide and ignorada and fila[7] is None,
                     f"huella base = Python: {coincide}, huella enviada ignorada: {ignorada}, previa nula: {fila[7] is None}")


def v02(app, mig):
    e = Escenario(app)
    ctx = e.base()
    segunda = e.version(ctx["medicion"], 2, ctx["tecnico"], co2e=Decimal("101.5"))
    primera, fila = leer_version(e, ctx["version"]), leer_version(e, segunda)
    encadena = fila[7] == primera[6]
    coincide = fila[6] == huella_esperada(fila)
    return resultado(encadena and coincide, f"huella_previa = huella v1: {encadena}, huella base = Python: {coincide}")


def v03(app, mig):
    e = Escenario(app)
    ctx = e.base()
    obtenido = intento(app, lambda: e.version(ctx["medicion"], 3, ctx["tecnico"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def v04(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.actor(ctx["tecnico"])
    obtenidos = [
        intento(app, lambda: app.execute("UPDATE mediciones_medicionversion SET notas = 'x' WHERE id = %s", (ctx["version"],))),
        intento(app, lambda: app.execute("DELETE FROM mediciones_medicionversion WHERE id = %s", (ctx["version"],))),
        intento(app, lambda: app.execute("TRUNCATE mediciones_medicionversion")),
    ]
    liberar(app)
    # CASCADE evita el rechazo previo por llaves foráneas y obliga a pasar por los disparadores.
    obtenidos.append(intento(mig, lambda: mig.execute("TRUNCATE mediciones_medicionversion CASCADE")))
    ok = obtenidos == [SIN_PERMISO, SIN_PERMISO, SIN_PERMISO, INTEGRIDAD]
    return resultado(ok, f"UPDATE {obtenidos[0]}, DELETE {obtenidos[1]}, TRUNCATE {obtenidos[2]}; TRUNCATE CASCADE migrador {obtenidos[3]}")


def v05(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"])
    presentada = intento(app, lambda: e.version(ctx["medicion"], 2, ctx["tecnico"]))
    otro = e.base()
    e.cerrar(otro["periodo"], otro["r7"])
    cerrada = intento(app, lambda: e.version(otro["medicion"], 2, otro["tecnico"]))
    return resultado(presentada == INTEGRIDAD and cerrada == INTEGRIDAD, f"presentada {presentada}; período cerrado {cerrada}")


def s01(app, mig):
    e = Escenario(app)
    ctx = e.base()
    obtenido = intento(app, lambda: e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"]))
    return resultado(obtenido == PASA, obtenido)


def s02(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.cerrar(ctx["periodo"], ctx["r7"])
    obtenido = intento(app, lambda: e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"]))
    return resultado(obtenido == INTEGRIDAD, f"{obtenido} (al cerrar, el borrador quedó sin_presentar)")


def s03(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"])
    obtenido = intento(app, lambda: e.aprobar(ctx["medicion"], ctx["version"], ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def s04(app, mig):
    e = Escenario(app)
    ctx = e.base()
    obtenido = intento(app, lambda: e.cambiar_estado(ctx["medicion"], "aprobada", ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def s05(app, mig):
    e = Escenario(app)
    ctx = e.base()
    otra_parcela = e.parcela(ctx["finca"])
    e.asignar(ctx["tecnico"], otra_parcela)
    presentada = e.medicion(ctx["tecnico"], otra_parcela, ctx["periodo"])
    e.version(presentada, 1, ctx["tecnico"])
    e.cambiar_estado(presentada, "presentada", ctx["tecnico"])
    e.cerrar(ctx["periodo"], ctx["r7"])
    borrador = e.estado(ctx["medicion"], ctx["r7"])[0]
    otra = e.estado(presentada, ctx["r7"])[0]
    return resultado(borrador == "sin_presentar" and otra == "presentada", f"borrador pasó a {borrador}; presentada quedó {otra}")


def s06(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    obtenido = intento(app, lambda: e.cambiar_estado(ctx["medicion"], "devuelta", ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def a01(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    obtenido = intento(app, lambda: e.aprobar(ctx["medicion"], ctx["version"], ctx["r2"]))
    estado = e.estado(ctx["medicion"], ctx["r2"])[0]
    return resultado(obtenido == PASA and estado == "aprobada", f"{obtenido}, estado {estado}")


def a02(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    e.cambiar_rol(ctx["tecnico"], "R1", "R2")
    obtenido = intento(app, lambda: e.aprobar(ctx["medicion"], ctx["version"], ctx["tecnico"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def a03(app, mig):
    e = Escenario(app)
    ctx = e.aprobada(co2e=CO2E_ALTO)
    obtenido = intento(app, lambda: e.aprobar(ctx["medicion"], ctx["version"], ctx["r2"]))
    return resultado(obtenido == UNICIDAD, obtenido)


def a04(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.version(ctx["medicion"], 2, ctx["tecnico"])
    e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"])
    e.cerrar(ctx["periodo"], ctx["r7"])
    obtenido = intento(app, lambda: e.aprobar(ctx["medicion"], ctx["version"], ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def a05(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    obtenido = intento(app, lambda: e.aprobar(ctx["medicion"], ctx["version"], ctx["r7"]))
    return resultado(obtenido == SIN_PERMISO, obtenido)


def c01(app, mig):
    e = Escenario(app)
    ctx = e.aprobada()
    obtenido = intento(app, lambda: e.emitir(ctx, ctx["r2"]))
    estado = e.estado(ctx["medicion"], ctx["r2"])[0]
    return resultado(obtenido == PASA and estado == "certificada", f"{obtenido}, estado {estado}")


def c02(app, mig):
    e = Escenario(app)
    ctx = e.aprobada(co2e=CO2E_ALTO)
    obtenido = intento(app, lambda: e.emitir(ctx, ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def c03(app, mig):
    e = Escenario(app)
    ctx = e.aprobada(co2e=CO2E_ALTO)
    e.aprobar(ctx["medicion"], ctx["version"], e.usuario("R2"))
    obtenido = intento(app, lambda: e.emitir(ctx, ctx["r2"]))
    return resultado(obtenido == PASA, obtenido)


def c04a(app, mig):
    e = Escenario(app)
    ctx = e.certificada()
    obtenido = intento(app, lambda: e.emitir(ctx, ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, f"{obtenido} (el disparador lo rechaza antes del índice: la medición ya está certificada)")


def c04b(app, mig):
    """Índice único H1 sin disparadores: migrador quita FORCE y desactiva los de usuario en la transacción."""
    for tabla in ("mediciones_medicion", "mediciones_medicionversion", "mediciones_certificado"):
        mig.execute(f"ALTER TABLE {tabla} NO FORCE ROW LEVEL SECURITY")
    mig.execute("ALTER TABLE mediciones_certificado DISABLE TRIGGER USER")
    e = Escenario(mig)
    tecnico = e.usuario()
    parcela = e.parcela(e.finca())
    periodo = e.periodo()
    medicion = e.medicion(tecnico, parcela, periodo)
    version = e.version(medicion, 1, tecnico)
    ctx = {"parcela": parcela, "periodo": periodo, "medicion": medicion, "version": version}
    e.emitir(ctx, None)
    obtenido = intento(mig, lambda: e.emitir(ctx, None))
    return resultado(obtenido == UNICIDAD, obtenido)


def c05(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    sin_aprobacion = intento(app, lambda: e.emitir(ctx, ctx["r2"]))
    return resultado(sin_aprobacion == INTEGRIDAD, f"medición presentada sin aprobación: {sin_aprobacion}")


def c06(app, mig):
    e = Escenario(app)
    ctx = e.certificada()
    obtenido = intento(app, lambda: e.anular(ctx["certificado"], ctx["r7"]))
    estado, ciclo = e.estado(ctx["medicion"], ctx["r7"])
    return resultado(obtenido == PASA and estado == "presentada" and ciclo == 2, f"{obtenido}, medición {estado}, ciclo {ciclo}")


def c07(app, mig):
    e = Escenario(app)
    ctx = e.certificada()
    obtenido = intento(app, lambda: e.anular(ctx["certificado"], ctx["r7"], justificacion=None))
    return resultado(obtenido == CHECK, obtenido)


def c08(app, mig):
    e = Escenario(app)
    ctx = e.certificada()
    e.cambiar_rol(ctx["r2"], "R2", "R7")
    obtenido = intento(app, lambda: e.anular(ctx["certificado"], ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def c09(app, mig):
    e = Escenario(app)
    ctx = e.certificada()
    e.anular(ctx["certificado"], ctx["r7"])
    sin_aprobacion = intento(app, lambda: e.emitir(ctx, ctx["r2"]))
    e.aprobar(ctx["medicion"], ctx["version"], ctx["r2"], ciclo=2)
    con_aprobacion = intento(app, lambda: e.emitir(ctx, ctx["r2"]))
    e.actor(ctx["r2"])
    estados = sorted(r[0] for r in app.execute(
        "SELECT estado FROM mediciones_certificado WHERE medicion_id = %s", (ctx["medicion"],)).fetchall())
    ok = sin_aprobacion == INTEGRIDAD and con_aprobacion == PASA and estados == ["anulado", "vigente"]
    return resultado(ok, f"sin aprobación {sin_aprobacion}; con aprobación {con_aprobacion}; certificados {estados}")


def c10(app, mig):
    e = Escenario(app)
    ctx = e.certificada()
    e.actor(ctx["r7"])
    columna = intento(app, lambda: app.execute("UPDATE mediciones_certificado SET ciclo = 5 WHERE id = %s", (ctx["certificado"],)))
    borrado = intento(app, lambda: app.execute("DELETE FROM mediciones_certificado WHERE id = %s", (ctx["certificado"],)))
    return resultado(columna == SIN_PERMISO and borrado == SIN_PERMISO, f"UPDATE ciclo {columna}, DELETE {borrado}")


def e01(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    obtenido = intento(app, lambda: e.enmienda(ctx["medicion"], ctx["tecnico"]))
    return resultado(obtenido == PASA, obtenido)


def certificada_con_plazo_vencido(mig) -> tuple[Escenario, dict]:
    """Medición certificada cuyo período cerró hace DIAS_FUERA_DE_PLAZO días.

    El cierre real fija cerrado_en = now(); para simular el paso del tiempo, el migrador (dueño),
    dentro de la transacción que se revierte, desactiva solo el disparador que fija la fecha y
    quita FORCE para operar sin políticas. Las reglas de la enmienda siguen activas.
    """
    mig.execute("ALTER TABLE mediciones_periodo DISABLE TRIGGER mediciones_periodo_inmutable")
    for tabla in TABLAS_RLS:
        mig.execute(f"ALTER TABLE {tabla} NO FORCE ROW LEVEL SECURITY")
    e = Escenario(mig)
    ctx = e.base()
    e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"])
    e.afectar(
        "UPDATE mediciones_periodo SET estado = 'cerrado', cerrado_en = now() - make_interval(days => %s),"
        " cerrado_por_id = %s WHERE id = %s",
        (DIAS_FUERA_DE_PLAZO, ctx["r7"], ctx["periodo"]),
    )
    e.aprobar(ctx["medicion"], ctx["version"], ctx["r2"])
    ctx["certificado"] = e.emitir(ctx, ctx["r2"])
    return e, ctx


def e02(app, mig):
    e, ctx = certificada_con_plazo_vencido(mig)
    obtenido = intento(mig, lambda: e.enmienda(ctx["medicion"], ctx["tecnico"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def e03(app, mig):
    e, ctx = certificada_con_plazo_vencido(mig)
    e.anular(ctx["certificado"], ctx["r7"])
    obtenido = intento(mig, lambda: e.enmienda(ctx["medicion"], ctx["tecnico"]))
    return resultado(obtenido == PASA, obtenido)


def e04(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    ajeno = e.usuario("R1")
    obtenido = intento(app, lambda: e.enmienda(ctx["medicion"], ajeno))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def e05(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"])
    obtenido = intento(app, lambda: e.enmienda(ctx["medicion"], ctx["tecnico"]))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def e06(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    enmienda = e.enmienda(ctx["medicion"], ctx["tecnico"])
    e.cambiar_rol(ctx["tecnico"], "R1", "R7")
    obtenido = intento(app, lambda: e.resolver(enmienda, ctx["tecnico"]))
    return resultado(obtenido == INTEGRIDAD, f"{obtenido} (solicitante, ahora R7)")


def e07(app, mig):
    e = Escenario(app)
    ctx = e.aprobada()
    enmienda = e.enmienda(ctx["medicion"], ctx["r2"])
    e.cambiar_rol(ctx["tecnico"], "R1", "R7")
    obtenido = intento(app, lambda: e.resolver(enmienda, ctx["tecnico"]))
    return resultado(obtenido == INTEGRIDAD, f"{obtenido} (registrante, ahora R7)")


def e08(app, mig):
    e = Escenario(app)
    ctx = e.aprobada()
    enmienda = e.enmienda(ctx["medicion"], ctx["tecnico"])
    e.cambiar_rol(ctx["r2"], "R2", "R7")
    obtenido = intento(app, lambda: e.resolver(enmienda, ctx["r2"]))
    return resultado(obtenido == INTEGRIDAD, f"{obtenido} (aprobador, ahora R7)")


def enmienda_autorizada(e: Escenario) -> tuple[dict, uuid.UUID]:
    ctx = e.presentada_y_cerrada()
    enmienda = e.enmienda(ctx["medicion"], ctx["tecnico"])
    e.resolver(enmienda, ctx["r7"])
    return ctx, enmienda


def version_de_enmienda(e: Escenario, ctx: dict, enmienda, numero: int = 2, co2e=Decimal("150.000")) -> uuid.UUID:
    return e.version(ctx["medicion"], numero, ctx["tecnico"], co2e=co2e, fecha=date(2026, 2, 1),
                     notas="Muestreo corregido", enmienda=enmienda)


def e09(app, mig):
    e = Escenario(app)
    ctx, enmienda = enmienda_autorizada(e)
    nueva = {}
    obtenido = intento(app, lambda: nueva.setdefault("id", version_de_enmienda(e, ctx, enmienda)))
    if obtenido != PASA:
        return resultado(False, obtenido)
    primera, fila = leer_version(e, ctx["version"]), leer_version(e, nueva["id"])
    valores = (fila[2], fila[3], fila[4]) == (Decimal("150.000"), date(2026, 2, 1), "Muestreo corregido")
    encadena = fila[7] == primera[6] and fila[6] == huella_esperada(fila)
    return resultado(valores and encadena, f"{obtenido}, valores propuestos={valores}, huella encadenada={encadena}")


def e10(app, mig):
    e = Escenario(app)
    ctx, enmienda = enmienda_autorizada(e)
    obtenido = intento(app, lambda: version_de_enmienda(e, ctx, enmienda, co2e=Decimal("151.000")))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def e11(app, mig):
    e = Escenario(app)
    ctx, enmienda = enmienda_autorizada(e)
    version_de_enmienda(e, ctx, enmienda)
    obtenido = intento(app, lambda: version_de_enmienda(e, ctx, enmienda, numero=3))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def e12(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    enmienda = e.enmienda(ctx["medicion"], ctx["tecnico"])
    obtenido = intento(app, lambda: version_de_enmienda(e, ctx, enmienda))
    return resultado(obtenido == INTEGRIDAD, obtenido)


def e13(app, mig):
    e = Escenario(app)
    ctx = e.presentada_y_cerrada()
    e.enmienda(ctx["medicion"], ctx["tecnico"])
    obtenido = intento(app, lambda: e.enmienda(ctx["medicion"], ctx["tecnico"]))
    return resultado(obtenido == UNICIDAD, obtenido)


def e14(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.cerrar(ctx["periodo"], ctx["r7"])
    inicial = e.estado(ctx["medicion"], ctx["tecnico"])[0]
    enmienda = e.enmienda(ctx["medicion"], ctx["tecnico"])
    e.resolver(enmienda, ctx["r7"])
    version = intento(app, lambda: version_de_enmienda(e, ctx, enmienda))
    presentar = intento(app, lambda: e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"]))
    final = e.estado(ctx["medicion"], ctx["tecnico"])[0]
    ok = inicial == "sin_presentar" and version == PASA and presentar == PASA and final == "presentada"
    return resultado(ok, f"{inicial}; versión {version}; presentar {presentar}; estado {final}")


# RLS


CONSULTAS_RLS = {
    "mediciones_medicion": "SELECT id FROM mediciones_medicion WHERE id = ANY(%s)",
    "mediciones_medicionversion": "SELECT medicion_id FROM mediciones_medicionversion WHERE medicion_id = ANY(%s)",
    "mediciones_aprobacion": "SELECT medicion_id FROM mediciones_aprobacion WHERE medicion_id = ANY(%s)",
    "mediciones_enmienda": "SELECT medicion_id FROM mediciones_enmienda WHERE medicion_id = ANY(%s)",
    "mediciones_certificado": "SELECT medicion_id FROM mediciones_certificado WHERE medicion_id = ANY(%s)",
}


def visibles(e: Escenario, actor, mediciones: list) -> dict[str, set]:
    e.actor(actor)
    return {t: {r[0] for r in e.sql(q, (mediciones,)).fetchall()} for t, q in CONSULTAS_RLS.items()}


def escenario_rls(e: Escenario) -> dict:
    ctx = {"tecnico": e.usuario("R1"), "r2": e.usuario("R2"), "r7": e.usuario("R7"),
           "dueno": e.usuario("R6"), "auditor": e.usuario("R5")}
    ctx["periodo"] = e.periodo(ctx["r7"])
    for clave in ("a", "b"):
        finca = e.finca()
        parcela = e.parcela(finca)
        e.asignar(ctx["tecnico"], parcela)
        medicion = e.medicion(ctx["tecnico"], parcela, ctx["periodo"])
        version = e.version(medicion, 1, ctx["tecnico"])
        e.cambiar_estado(medicion, "presentada", ctx["tecnico"])
        ctx[clave] = {"finca": finca, "parcela": parcela, "periodo": ctx["periodo"], "medicion": medicion, "version": version}
    e.propiedad(ctx["dueno"], ctx["a"]["finca"])
    e.cerrar(ctx["periodo"], ctx["r7"])
    for clave in ("a", "b"):
        datos = ctx[clave]
        e.aprobar(datos["medicion"], datos["version"], ctx["r2"])
        e.emitir(datos, ctx["r2"])
        e.enmienda(datos["medicion"], ctx["tecnico"])
    return ctx


def pruebas_rls(app, mig) -> list[tuple[str, str, str, bool, str]]:
    e = Escenario(app)
    ctx = escenario_rls(e)
    a, b = ctx["a"]["medicion"], ctx["b"]["medicion"]
    ambas = [a, b]
    filas = []

    dueno = visibles(e, ctx["dueno"], ambas)
    solo_a = all(v == {a} for v in dueno.values())
    filas.append(("R01", "Dueño (R6) ve las 5 tablas solo de su finca", "1 fila por tabla, de su finca",
                  solo_a, f"tablas con solo su finca: {sum(v == {a} for v in dueno.values())}/5"))
    filas.append(("R02", "Dueño (R6) no ve los datos de otra finca", "0 filas de la otra finca",
                  all(b not in v for v in dueno.values()), f"tablas donde ve la otra finca: {sum(b in v for v in dueno.values())}"))

    sin_ventana = visibles(e, ctx["auditor"], ambas)
    e.ventana(ctx["auditor"], ctx["r7"], ctx["r2"])
    con_ventana = visibles(e, ctx["auditor"], ambas)
    filas.append(("R03", "Auditor (R5): sin ventana 0 filas; con ventana vigente, todas", "0 y luego todas",
                  all(not v for v in sin_ventana.values()) and all(v == set(ambas) for v in con_ventana.values()),
                  f"sin ventana {sum(len(v) for v in sin_ventana.values())} filas; con ventana {sum(len(v) for v in con_ventana.values())} de 10"))

    sin_actor = visibles(e, None, ambas)
    filas.append(("R04", "Sin actor no se ven filas", "0 filas", all(not v for v in sin_actor.values()),
                  f"{sum(len(v) for v in sin_actor.values())} filas"))

    r2, r7 = visibles(e, ctx["r2"], ambas), visibles(e, ctx["r7"], ambas)
    filas.append(("R05", "R2 y R7 ven todas las filas", "10 y 10",
                  all(v == set(ambas) for v in r2.values()) and all(v == set(ambas) for v in r7.values()),
                  f"R2 {sum(len(v) for v in r2.values())}, R7 {sum(len(v) for v in r7.values())}"))

    sin_lectura = {
        "sin roles": visibles(e, e.usuario(), ambas),
        "solo R3": visibles(e, e.usuario("R3"), ambas),
        "solo R4": visibles(e, e.usuario("R4"), ambas),
    }
    filas.append(("L01", "Sin roles, solo R3 y solo R4 no ven filas en las 5 tablas", "0, 0 y 0",
                  all(not v for vistas in sin_lectura.values() for v in vistas.values()),
                  "; ".join(f"{k} {sum(len(v) for v in vistas.values())}" for k, vistas in sin_lectura.items())))

    tecnico = visibles(e, ctx["tecnico"], ambas)
    filas.append(("L02", "R1 conserva su alcance de lectura (todas las filas)", "10",
                  all(v == set(ambas) for v in tecnico.values()), f"R1 {sum(len(v) for v in tecnico.values())}"))

    mixto = visibles(e, e.usuario("R3", "R1"), ambas)
    filas.append(("L03", "Usuario con R3 y R1 conserva el acceso de R1", "10",
                  all(v == set(ambas) for v in mixto.values()), f"R3+R1 {sum(len(v) for v in mixto.values())}"))

    desactivar =[intento(app, lambda t=t: app.execute(f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY")) for t in TABLAS_RLS]
    quitar_force = [intento(app, lambda t=t: app.execute(f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY")) for t in TABLAS_RLS]
    filas.append(("R06", "app_rw no puede desactivar la RLS", "falla 42501 en las 5 tablas",
                  all(x == SIN_PERMISO for x in desactivar + quitar_force),
                  f"DISABLE: {sorted(set(desactivar))}; NO FORCE: {sorted(set(quitar_force))}"))
    return filas


def r07(app, mig):
    e = Escenario(mig)
    tecnico = e.usuario()
    parcela = e.parcela(e.finca())
    periodo = e.periodo()
    insertar_con_force = intento(mig, lambda: e.medicion(tecnico, parcela, periodo))
    mig.execute("ALTER TABLE mediciones_medicion NO FORCE ROW LEVEL SECURITY")
    medicion = e.medicion(tecnico, parcela, periodo)
    sin_force = e.uno("SELECT count(*) FROM mediciones_medicion WHERE id = %s", (medicion,))
    # Las llaves foráneas de Django son diferidas; ALTER TABLE exige que no queden comprobaciones pendientes.
    mig.execute("SET CONSTRAINTS ALL IMMEDIATE")
    mig.execute("ALTER TABLE mediciones_medicion FORCE ROW LEVEL SECURITY")
    con_force = e.uno("SELECT count(*) FROM mediciones_medicion WHERE id = %s", (medicion,))
    ok = insertar_con_force == SIN_PERMISO and sin_force == 1 and con_force == 0
    return resultado(ok, f"insertar con FORCE {insertar_con_force}; ve su fila sin FORCE={sin_force}, con FORCE={con_force}")


def d01(app, mig):
    obtenidos = []
    for tabla in TABLAS_NUEVAS:
        obtenidos.append(intento(app, lambda t=tabla: app.execute(f"DELETE FROM {t}")))
        obtenidos.append(intento(app, lambda t=tabla: app.execute(f"TRUNCATE {t}")))
    ok = all(x == SIN_PERMISO for x in obtenidos)
    return resultado(ok, f"{sum(x == SIN_PERMISO for x in obtenidos)}/{len(obtenidos)} rechazos 42501 (DELETE y TRUNCATE en 7 tablas)")


def d02(app, mig):
    e = Escenario(app)
    ctx = e.base()
    e.actor(ctx["r2"])
    sentencias = [
        "UPDATE mediciones_medicion SET registrada_por_id = registrada_por_id",
        "UPDATE mediciones_medicionversion SET numero = numero",
        "UPDATE mediciones_enmienda SET motivo = motivo",
        "UPDATE mediciones_certificado SET ciclo = ciclo",
        "UPDATE mediciones_alerta SET tipo = tipo",
    ]
    obtenidos = [intento(app, lambda s=s: app.execute(s)) for s in sentencias]
    return resultado(all(x == SIN_PERMISO for x in obtenidos), f"{sum(x == SIN_PERMISO for x in obtenidos)}/{len(obtenidos)} rechazos 42501")


def d03(app, mig):
    e = Escenario(app)
    ctx = e.base()
    alerta = uuid.uuid4()
    insertar = intento(app, lambda: app.execute(
        "INSERT INTO mediciones_alerta (id, tipo, prioridad, usuario_id, parcela_id, medicion_id, detalle, creada_en)"
        " VALUES (%s, %s, 'aviso', %s, %s, %s, '{}'::jsonb, now())",
        (alerta, "prueba", ctx["tecnico"], ctx["parcela"], ctx["medicion"])))
    resolver = intento(app, lambda: e.afectar(
        "UPDATE mediciones_alerta SET resuelta_en = now(), resuelta_por_id = %s WHERE id = %s", (ctx["r7"], alerta)))
    otra_vez = intento(app, lambda: e.afectar(
        "UPDATE mediciones_alerta SET resuelta_en = now(), resuelta_por_id = %s WHERE id = %s", (ctx["r7"], alerta)))
    parametros = intento(app, lambda: app.execute("SELECT count(*) FROM mediciones_politicaparametro"))
    flujo = intento(app, lambda: e.cambiar_estado(ctx["medicion"], "presentada", ctx["tecnico"]))
    ok = [insertar, resolver, otra_vez, parametros, flujo] == [PASA, PASA, INTEGRIDAD, PASA, PASA]
    return resultado(ok, f"alerta {insertar}, resolver {resolver}, resolver de nuevo {otra_vez}, leer parámetros {parametros}, presentar {flujo}")


def x01(app, mig):
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    from django.db import connection

    from mediciones.contexto import como_actor

    actor = uuid.uuid4()

    def valor():
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('app.usuario_id', true)")
            return cursor.fetchone()[0]

    with como_actor(actor):
        dentro = valor()
    fuera = valor()
    connection.close()
    ok = dentro == str(actor) and not fuera
    return resultado(ok, f"dentro igual al actor={dentro == str(actor)}, fuera vacío={not fuera}")


# --------------------------------------------------------------------------- ejecución


@dataclass(frozen=True)
class Resultado:
    id: str
    descripcion: str
    esperado: str
    obtenido: str
    ok: bool


PRUEBAS = [
    ("P01", "Parámetros sembrados con los valores de la política", "10 valores correctos", p01),
    ("P02", "Parámetros: UPDATE, DELETE y TRUNCATE rechazados (app_rw y migrador)", "42501 x3; 23000 x3", p02),
    ("PE01", "Abrir período como R1 a R6 o sin actor", "23000 x7", pe01),
    ("PE02", "Abrir período como R7", PASA, pe02),
    ("PE03", "Cerrar período como R1 a R6 o sin actor", "23000 x7", pe03),
    ("PE04", "Cierre por R7: la base fija cerrado_en = now() y cerrado_por = actor", "pasa; fecha y autor de la base", pe04),
    ("PE05", "Reabrir un período cerrado, incluso como R7", INTEGRIDAD, pe05),
    ("M01", "R1 asignado registra en período abierto", PASA, m01),
    ("M02", "R1 no asignado no registra (RLS)", SIN_PERMISO, m02),
    ("M03", "Registro con período cerrado", INTEGRIDAD, m03),
    ("M04", "registrada_por distinto del actor (RLS)", SIN_PERMISO, m04),
    ("M05", "Sin actor: no ve filas ni inserta", "0 filas, 42501", m05),
    ("M06", "UPDATE de parcela o período de una medición", "42501, 42501", m06),
    ("V01", "Huella calculada por la base igual a calcular_huella; la enviada se ignora", "iguales, ignorada", v01),
    ("V02", "La segunda versión encadena huella_previa", "encadenada", v02),
    ("V03", "Número de versión fuera de secuencia", INTEGRIDAD, v03),
    ("V04", "UPDATE, DELETE y TRUNCATE de versiones (TRUNCATE también migrador)", "42501 x3; 23000", v04),
    ("V05", "Versión sin enmienda con medición presentada o período cerrado (AM-01)", "23000, 23000", v05),
    ("S01", "Presentar con período abierto", PASA, s01),
    ("S02", "Presentar después del cierre del período", INTEGRIDAD, s02),
    ("S03", "Aprobar con período abierto", INTEGRIDAD, s03),
    ("S04", "Borrador a aprobada", INTEGRIDAD, s04),
    ("S05", "Al cerrar el período los borradores pasan a sin_presentar", "sin_presentar; presentada intacta", s05),
    ("S06", "Devolver sin devuelta_por", INTEGRIDAD, s06),
    ("A01", "Aprobación por R2 distinto del registrante; queda aprobada", "pasa, aprobada", a01),
    ("A02", "Aprueba quien registró (luego R2) (Cd8)", INTEGRIDAD, a02),
    ("A03", "El mismo aprobador dos veces en el ciclo", UNICIDAD, a03),
    ("A04", "Aprobación de una versión que no es la última", INTEGRIDAD, a04),
    ("A05", "Aprobación sin rol R2 (RLS)", SIN_PERMISO, a05),
    ("C01", "Certificado con una aprobación y <= 500 t; queda certificada", "pasa, certificada", c01),
    ("C02", "Más de 500 t con una sola aprobación", INTEGRIDAD, c02),
    ("C03", "Más de 500 t con dos aprobadores distintos", PASA, c03),
    ("C04a", "Segundo certificado vigente por el flujo normal (disparador)", INTEGRIDAD, c04a),
    ("C04b", "Segundo certificado vigente contra el índice único (sin disparadores, migrador)", UNICIDAD, c04b),
    ("C05", "Emisión sin aprobación o con la medición en otro estado", INTEGRIDAD, c05),
    ("C06", "Anulación por R7 con justificación; medición presentada, ciclo 2", "pasa, presentada, 2", c06),
    ("C07", "Anulación sin justificación", CHECK, c07),
    ("C08", "Anulación por quien aprobó (luego R7) (Cd20)", INTEGRIDAD, c08),
    ("C09", "Tras anular: sin aprobación del ciclo 2 falla; con ella pasa", "23000; pasa; anulado y vigente", c09),
    ("C10", "UPDATE de otra columna o DELETE del certificado", "42501, 42501", c10),
    ("E01", "Enmienda dentro de 90 días por el registrante", PASA, e01),
    ("E02", "Enmienda a los 91 días con certificado vigente", INTEGRIDAD, e02),
    ("E03", "Enmienda a los 91 días con certificado anulado", PASA, e03),
    ("E04", "Solicitante sin vínculo con la medición", INTEGRIDAD, e04),
    ("E05", "Enmienda con período abierto", INTEGRIDAD, e05),
    ("E06", "Autorizador igual al solicitante", INTEGRIDAD, e06),
    ("E07", "Autorizador igual al registrante", INTEGRIDAD, e07),
    ("E08", "Autorizador que aprobó la medición", INTEGRIDAD, e08),
    ("E09", "R7 independiente autoriza y se crea la versión con enmienda", "valores idénticos, huella encadenada", e09),
    ("E10", "Versión con valores distintos a los autorizados", INTEGRIDAD, e10),
    ("E11", "Reutilizar la misma enmienda", INTEGRIDAD, e11),
    ("E12", "Versión con enmienda no autorizada", INTEGRIDAD, e12),
    ("E13", "Segunda enmienda solicitada para la misma medición", UNICIDAD, e13),
    ("E14", "Enmienda sobre medición sin_presentar crea versión y permite presentar", "sin_presentar; pasa; presentada", e14),
    ("RLS", "", "", pruebas_rls),
    ("R07", "Migrador (dueño con FORCE y sin política) no ve ni inserta", "42501; 1 sin FORCE, 0 con FORCE", r07),
    ("D01", "app_rw: DELETE y TRUNCATE en las 7 tablas nuevas", "14 rechazos 42501", d01),
    ("D02", "app_rw: UPDATE de columnas no concedidas", "5 rechazos 42501", d02),
    ("D03", "Operaciones permitidas con el actor correcto", "pasa; resolver dos veces falla", d03),
    ("X01", "como_actor fija app.usuario_id solo dentro de la transacción", "dentro igual, fuera vacío", x01),
]


def ejecutar(conexiones: dict, id_: str, descripcion: str, esperado: str, funcion) -> list[Resultado]:
    app, mig = conexiones[APP].cursor(), conexiones[MIGRADOR].cursor()
    try:
        salida = funcion(app, mig)
        if isinstance(salida, list):
            return [Resultado(*fila[:3], fila[4], fila[3]) for fila in salida]
        ok, obtenido = salida
        return [Resultado(id_, descripcion, esperado, obtenido, ok)]
    except psycopg.Error as error:
        detalle = PATRON_URL.sub("[REDACTADO]", (error.diag.message_primary or "")[:90])
        return [Resultado(id_, descripcion, esperado, f"excepción {error.sqlstate}: {detalle}", False)]
    except Exception as error:  # cualquier otra excepción es un fallo de la prueba
        return [Resultado(id_, descripcion, esperado, f"excepción {type(error).__name__}", False)]
    finally:
        for conexion in conexiones.values():
            conexion.rollback()


def conectar(rol: str) -> psycopg.Connection:
    variable = VARIABLES_CONEXION[rol]
    cadena = os.environ.get(variable)
    if not cadena:
        raise SystemExit(f"[FALLO] Falta la variable {variable}. Cargue antes: . .\\scripts\\entorno_dev.ps1 -Pruebas")
    try:
        conexion = psycopg.connect(cadena, autocommit=True, connect_timeout=15)
    except psycopg.Error as error:
        raise SystemExit(f"[FALLO] No se pudo conectar como {rol}: {PATRON_URL.sub('[REDACTADO]', str(error))}") from None
    # Ajuste de sesión fuera de toda transacción: un lock entre las dos conexiones falla en 10 s.
    conexion.execute("SET lock_timeout = '10s'")
    conexion.autocommit = False
    return conexion


def conteos(conexion: psycopg.Connection) -> dict[str, int]:
    """Conteos reales con un actor R7 temporal (ve todas las filas); la transacción se revierte."""
    cur = conexion.cursor()
    try:
        usuarios = cur.execute("SELECT count(*) FROM usuarios_usuario").fetchone()[0]
        e = Escenario(cur)
        e.actor(e.usuario("R7"))
        totales = {t: cur.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in TABLAS_NUEVAS}
        totales["mediciones_periodo"] = cur.execute("SELECT count(*) FROM mediciones_periodo").fetchone()[0]
        totales["usuarios_usuario"] = usuarios
        return totales
    finally:
        conexion.rollback()


def imprimir_tabla(resultados: list[Resultado]) -> None:
    encabezado = ("id", "descripción", "esperado", "obtenido", "OK/FALLA")
    filas = [(r.id, r.descripcion, r.esperado, r.obtenido, "OK" if r.ok else "FALLA") for r in resultados]
    anchos = [max(len(encabezado[i]), *(len(f[i]) for f in filas)) for i in range(len(encabezado))]
    print(" | ".join(h.ljust(anchos[i]) for i, h in enumerate(encabezado)))
    print("-+-".join("-" * a for a in anchos))
    for fila in filas:
        print(" | ".join(v.ljust(anchos[i]) for i, v in enumerate(fila)))


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    conexiones = {rol: conectar(rol) for rol in VARIABLES_CONEXION}
    try:
        iniciales = conteos(conexiones[APP])
        resultados = []
        for id_, descripcion, esperado, funcion in PRUEBAS:
            resultados.extend(ejecutar(conexiones, id_, descripcion, esperado, funcion))
        finales = conteos(conexiones[APP])
    finally:
        for conexion in conexiones.values():
            conexion.rollback()
            conexion.close()
    imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    print(f"\nTotal: {correctas}/{len(resultados)} OK")
    limpio = finales == iniciales
    print(f"Conteos antes: {iniciales}")
    print(f"Conteos después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio else 1


if __name__ == "__main__":
    sys.exit(main())
