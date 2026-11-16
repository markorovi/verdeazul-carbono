#!/usr/bin/env python3
"""Pruebas de reglas y permisos del esquema contra la base dev de Neon.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_bd.py

Cada prueba corre en su propia transacción, que siempre se revierte: no deja datos.
Las conexiones se toman de DATABASE_URL_APP (app_rw) y DATABASE_URL_MIGRADOR (migrador);
sus valores nunca se imprimen.
"""

from __future__ import annotations

import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from itertools import combinations
from typing import Callable

import psycopg

APP = "app_rw"
MIGRADOR = "migrador"
VARIABLES_CONEXION = {APP: "DATABASE_URL_APP", MIGRADOR: "DATABASE_URL_MIGRADOR"}
PATRON_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")

PASA = "pasa"
CUALQUIER_ERROR = "*"
INTEGRIDAD = "23000"
UNICIDAD = "23505"
CHECK = "23514"
SIN_PERMISO = "42501"

HASH_FICTICIO = "!no-usable"
DOMINIO_PRUEBA = "ejemplo.invalid"
ROLES = ("R1", "R2", "R3", "R4", "R5", "R6", "R7")
PARES_PERMITIDOS = {("R1", "R3"), ("R3", "R4")}

SRID = 5367
SRID_AJENO = 4326
# Cuadrados de 100 m en CRTM05 (EPSG:5367), en una zona sin parcelas reales.
X0, Y0, LADO = 300000, 900000, 100

AHORA = datetime.now(timezone.utc)
PERIODO_INICIO = date(2099, 1, 1)
PERIODO_FIN = date(2099, 12, 31)

Contexto = dict
Preparacion = Callable[[psycopg.Cursor], Contexto]
Accion = Callable[[psycopg.Cursor, Contexto], None]


def cuadrado(x: float, y: float) -> str:
    """WKT de un cuadrado de lado LADO con esquina inferior izquierda en (x, y)."""
    return f"POLYGON(({x} {y}, {x + LADO} {y}, {x + LADO} {y + LADO}, {x} {y + LADO}, {x} {y}))"


def lazo(x: float, y: float) -> str:
    """WKT de un polígono inválido que se cruza a sí mismo."""
    return f"POLYGON(({x} {y}, {x + LADO} {y + LADO}, {x + LADO} {y}, {x} {y + LADO}, {x} {y}))"


WKT_BASE = cuadrado(X0, Y0)
WKT_TRASLAPADO = cuadrado(X0 + LADO / 2, Y0)
WKT_BORDE_COMPARTIDO = cuadrado(X0 + LADO, Y0)
WKT_INVALIDO = lazo(X0, Y0)


# --------------------------------------------------------------------------- datos de apoyo


def nuevo_usuario(cur: psycopg.Cursor) -> uuid.UUID:
    usuario_id = uuid.uuid4()
    cur.execute(
        "INSERT INTO usuarios_usuario (id, password, correo, nombre, activo, creado_en)"
        " VALUES (%s, %s, %s, %s, true, now())",
        (usuario_id, HASH_FICTICIO, f"prueba-{usuario_id}@{DOMINIO_PRUEBA}", "Usuario de prueba"),
    )
    return usuario_id


def asignar_rol(cur: psycopg.Cursor, usuario_id: uuid.UUID, rol: str) -> None:
    cur.execute(
        "INSERT INTO usuarios_rolusuario (id, usuario_id, rol_id, desde) VALUES (%s, %s, %s, now())",
        (uuid.uuid4(), usuario_id, rol),
    )


def usuario_con_roles(cur: psycopg.Cursor, *roles: str) -> uuid.UUID:
    usuario_id = nuevo_usuario(cur)
    for rol in roles:
        asignar_rol(cur, usuario_id, rol)
    return usuario_id


def nueva_finca(cur: psycopg.Cursor) -> uuid.UUID:
    finca_id = uuid.uuid4()
    cur.execute(
        "INSERT INTO catalogo_finca (id, nombre, creada_en) VALUES (%s, %s, now())",
        (finca_id, "Finca de prueba"),
    )
    return finca_id


def nueva_parcela(cur: psycopg.Cursor, finca_id: uuid.UUID, wkt: str, srid: int = SRID) -> uuid.UUID:
    parcela_id = uuid.uuid4()
    cur.execute(
        "INSERT INTO catalogo_parcela (id, finca_id, codigo, geom)"
        " VALUES (%s, %s, %s, ST_GeomFromText(%s, %s))",
        (parcela_id, finca_id, f"P-{parcela_id.hex[:8]}", wkt, srid),
    )
    return parcela_id


def nuevo_periodo(cur: psycopg.Cursor) -> uuid.UUID:
    periodo_id = uuid.uuid4()
    cur.execute(
        "INSERT INTO mediciones_periodo (id, inicio, fin, estado) VALUES (%s, %s, %s, 'abierto')",
        (periodo_id, PERIODO_INICIO, PERIODO_FIN),
    )
    return periodo_id


def cerrar_periodo(cur: psycopg.Cursor, periodo_id: uuid.UUID, cerrado_por=None) -> None:
    cur.execute(
        "UPDATE mediciones_periodo SET estado = 'cerrado', cerrado_en = now(), cerrado_por_id = %s"
        " WHERE id = %s",
        (cerrado_por, periodo_id),
    )


def nuevo_acceso_emergencia(
    cur: psycopg.Cursor, beneficiario, r4, r7, horas: float, perfil: str
) -> None:
    cur.execute(
        "INSERT INTO usuarios_accesoemergencia"
        " (id, beneficiario_id, autorizado_por_r4_id, autorizado_por_r7_id, perfil, inicio, fin)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (uuid.uuid4(), beneficiario, r4, r7, perfil, AHORA, AHORA + timedelta(hours=horas)),
    )


def nueva_asignacion(cur: psycopg.Cursor, tecnico_id, parcela_id, dias: int) -> None:
    cur.execute(
        "INSERT INTO catalogo_asignacion (id, tecnico_id, parcela_id, desde, hasta)"
        " VALUES (%s, %s, %s, %s, %s)",
        (uuid.uuid4(), tecnico_id, parcela_id, AHORA, AHORA + timedelta(days=dias)),
    )


# --------------------------------------------------------------------------- preparaciones


def sin_preparacion(cur: psycopg.Cursor) -> Contexto:
    return {}


def tres_usuarios(cur: psycopg.Cursor) -> Contexto:
    return {"a": nuevo_usuario(cur), "b": nuevo_usuario(cur), "c": nuevo_usuario(cur)}


def finca_vacia(cur: psycopg.Cursor) -> Contexto:
    return {"finca": nueva_finca(cur)}


def finca_con_parcela_base(cur: psycopg.Cursor) -> Contexto:
    finca = nueva_finca(cur)
    nueva_parcela(cur, finca, WKT_BASE)
    return {"finca": finca}


def parcela_con_tecnico(cur: psycopg.Cursor, *roles: str) -> Contexto:
    return {
        "tecnico": usuario_con_roles(cur, *roles),
        "parcela": nueva_parcela(cur, nueva_finca(cur), WKT_BASE),
    }


def parcela_con_tecnico_r1(cur: psycopg.Cursor) -> Contexto:
    return parcela_con_tecnico(cur, "R1")


def periodo_abierto(cur: psycopg.Cursor) -> Contexto:
    return {"periodo": nuevo_periodo(cur), "usuario": nuevo_usuario(cur)}


def periodo_cerrado(cur: psycopg.Cursor) -> Contexto:
    periodo = nuevo_periodo(cur)
    cerrar_periodo(cur, periodo)
    return {"periodo": periodo}


def solo_periodo(cur: psycopg.Cursor) -> Contexto:
    return {"periodo": nuevo_periodo(cur)}


def con_id(crear: Callable[[psycopg.Cursor], uuid.UUID]) -> Preparacion:
    """Preparación que crea una fila con `crear` y deja su id en el contexto."""
    return lambda cur: {"id": crear(cur)}


def usuario_con_rol(rol: str) -> Preparacion:
    return lambda cur: {"usuario": usuario_con_roles(cur, rol)}


# --------------------------------------------------------------------------- acciones


def asignar_rol_al_usuario(rol: str) -> Accion:
    return lambda cur, ctx: asignar_rol(cur, ctx["usuario"], rol)


def insertar_parcela(wkt: str, srid: int = SRID) -> Accion:
    return lambda cur, ctx: nueva_parcela(cur, ctx["finca"], wkt, srid)


def asignar_tecnico(dias: int) -> Accion:
    return lambda cur, ctx: nueva_asignacion(cur, ctx["tecnico"], ctx["parcela"], dias)


def autorizar_emergencia(
    beneficiario: str, r4: str, r7: str, horas: float, perfil: str = "solo_lectura"
) -> Accion:
    return lambda cur, ctx: nuevo_acceso_emergencia(
        cur, ctx[beneficiario], ctx[r4], ctx[r7], horas, perfil
    )


def sentencia(sql: str, clave: str | None = None) -> Accion:
    """Ejecuta `sql`, con el id del contexto como único parámetro si se indica `clave`."""
    return lambda cur, ctx: cur.execute(sql, (ctx[clave],) if clave else None)


def cerrar_periodo_abierto(cur: psycopg.Cursor, ctx: Contexto) -> None:
    cerrar_periodo(cur, ctx["periodo"], ctx["usuario"])


def reabrir_periodo(cur: psycopg.Cursor, ctx: Contexto) -> None:
    cur.execute(
        "UPDATE mediciones_periodo SET estado = 'abierto', cerrado_en = NULL, cerrado_por_id = NULL"
        " WHERE id = %s",
        (ctx["periodo"],),
    )


def mover_fin_periodo(cur: psycopg.Cursor, ctx: Contexto) -> None:
    cur.execute("UPDATE mediciones_periodo SET fin = fin + 1 WHERE id = %s", (ctx["periodo"],))


def borrar_periodo(cur: psycopg.Cursor, ctx: Contexto) -> None:
    cur.execute("DELETE FROM mediciones_periodo WHERE id = %s", (ctx["periodo"],))


def ventana_sin_duracion(cur: psycopg.Cursor, ctx: Contexto) -> None:
    cur.execute(
        "INSERT INTO usuarios_ventanaauditoria"
        " (id, auditor_id, inicio, fin, abierta_por_id, solicitada_por_id)"
        " VALUES (%s, %s, %s, %s, %s, %s)",
        (uuid.uuid4(), ctx["a"], AHORA, AHORA, ctx["b"], ctx["c"]),
    )


def insertar_y_actualizar_usuario(cur: psycopg.Cursor, ctx: Contexto) -> None:
    usuario = nuevo_usuario(cur)
    cur.execute(
        "UPDATE usuarios_usuario SET nombre = %s, activo = false, last_login = now(),"
        " password = %s WHERE id = %s",
        ("Nombre cambiado", HASH_FICTICIO, usuario),
    )


def insertar_y_borrar_sesion(cur: psycopg.Cursor, ctx: Contexto) -> None:
    clave = uuid.uuid4().hex
    cur.execute(
        "INSERT INTO django_session (session_key, session_data, expire_date) VALUES (%s, %s, %s)",
        (clave, "datos-de-prueba", AHORA + timedelta(hours=1)),
    )
    cur.execute("DELETE FROM django_session WHERE session_key = %s", (clave,))


# --------------------------------------------------------------------------- catálogo de pruebas


@dataclass(frozen=True)
class Prueba:
    id: str
    descripcion: str
    conexion: str
    esperado: str
    preparar: Preparacion
    accion: Accion


def pruebas_roles() -> list[Prueba]:
    pruebas = [
        Prueba(
            f"R{numero:02d}",
            f"Roles {rol_a} y {rol_b} vigentes en el mismo usuario",
            APP,
            PASA if (rol_a, rol_b) in PARES_PERMITIDOS else INTEGRIDAD,
            usuario_con_rol(rol_a),
            asignar_rol_al_usuario(rol_b),
        )
        for numero, (rol_a, rol_b) in enumerate(combinations(ROLES, 2), start=1)
    ]
    pruebas.append(
        Prueba(
            "R22",
            "Mismo rol vigente dos veces para un usuario",
            APP,
            UNICIDAD,
            usuario_con_rol("R1"),
            asignar_rol_al_usuario("R1"),
        )
    )
    return pruebas


def pruebas_parcelas() -> list[Prueba]:
    return [
        Prueba("G01", "Parcela que se traslapa con otra", APP, INTEGRIDAD,
               finca_con_parcela_base, insertar_parcela(WKT_TRASLAPADO)),
        Prueba("G02", "Parcela que solo comparte un borde", APP, PASA,
               finca_con_parcela_base, insertar_parcela(WKT_BORDE_COMPARTIDO)),
        Prueba("G03", "Geometría inválida (lazo)", APP, CHECK,
               finca_vacia, insertar_parcela(WKT_INVALIDO)),
        Prueba("G04", "SRID distinto de 5367", APP, CUALQUIER_ERROR,
               finca_vacia, insertar_parcela(WKT_BASE, SRID_AJENO)),
    ]


def pruebas_asignaciones() -> list[Prueba]:
    return [
        Prueba("A01", "Asignación a usuario sin R1", APP, INTEGRIDAD,
               parcela_con_tecnico, asignar_tecnico(30)),
        Prueba("A02", "Asignación a usuario con R1 vigente", APP, PASA,
               parcela_con_tecnico_r1, asignar_tecnico(30)),
        Prueba("A03", "Asignación con hasta <= desde", APP, CHECK,
               parcela_con_tecnico_r1, asignar_tecnico(0)),
    ]


def pruebas_periodos() -> list[Prueba]:
    return [
        Prueba("P01", "Cerrar un período abierto", APP, PASA,
               periodo_abierto, cerrar_periodo_abierto),
        Prueba("P02", "Reabrir un período cerrado", APP, INTEGRIDAD,
               periodo_cerrado, reabrir_periodo),
        Prueba("P03", "Cambiar fechas de un período cerrado (migrador)", MIGRADOR, INTEGRIDAD,
               periodo_cerrado, mover_fin_periodo),
        Prueba("P04", "DELETE de un período (migrador)", MIGRADOR, INTEGRIDAD,
               solo_periodo, borrar_periodo),
    ]


def pruebas_emergencia() -> list[Prueba]:
    return [
        Prueba("E01", "Acceso de emergencia de 5 h", APP, CHECK,
               tres_usuarios, autorizar_emergencia("a", "b", "c", 5)),
        Prueba("E02", "Acceso de emergencia de 4 h", APP, PASA,
               tres_usuarios, autorizar_emergencia("a", "b", "c", 4)),
        Prueba("E03", "Beneficiario igual a un autorizador", APP, CHECK,
               tres_usuarios, autorizar_emergencia("a", "a", "c", 2)),
        Prueba("E04", "Mismo autorizador como R4 y R7", APP, CHECK,
               tres_usuarios, autorizar_emergencia("a", "b", "b", 2)),
        Prueba("E05", "Perfil distinto de solo_lectura", APP, CHECK,
               tres_usuarios, autorizar_emergencia("a", "b", "c", 2, "total")),
    ]


def pruebas_ventana() -> list[Prueba]:
    return [
        Prueba("V01", "Ventana de auditoría con fin <= inicio", APP, CHECK,
               tres_usuarios, ventana_sin_duracion),
    ]


def pruebas_permisos_app() -> list[Prueba]:
    return [
        Prueba("D01", "app_rw: DELETE en usuarios_usuario", APP, SIN_PERMISO,
               con_id(nuevo_usuario), sentencia("DELETE FROM usuarios_usuario WHERE id = %s", "id")),
        Prueba("D02", "app_rw: DELETE en catalogo_finca", APP, SIN_PERMISO,
               con_id(nueva_finca), sentencia("DELETE FROM catalogo_finca WHERE id = %s", "id")),
        Prueba("D03", "app_rw: DELETE en mediciones_periodo", APP, SIN_PERMISO,
               con_id(nuevo_periodo), sentencia("DELETE FROM mediciones_periodo WHERE id = %s", "id")),
        Prueba("D04", "app_rw: UPDATE de usuarios_usuario.correo", APP, SIN_PERMISO,
               con_id(nuevo_usuario),
               sentencia("UPDATE usuarios_usuario SET correo = 'otro@ejemplo.invalid' WHERE id = %s", "id")),
        Prueba("D05", "app_rw: TRUNCATE usuarios_usuario", APP, SIN_PERMISO,
               sin_preparacion, sentencia("TRUNCATE usuarios_usuario")),
        Prueba("D06", "app_rw: DROP TABLE usuarios_rol", APP, SIN_PERMISO,
               sin_preparacion, sentencia("DROP TABLE usuarios_rol")),
        Prueba("D07", "app_rw: INSERT y UPDATE permitidos en usuarios_usuario", APP, PASA,
               sin_preparacion, insertar_y_actualizar_usuario),
        Prueba("D08", "app_rw: INSERT y DELETE en django_session", APP, PASA,
               sin_preparacion, insertar_y_borrar_sesion),
    ]


def todas_las_pruebas() -> list[Prueba]:
    return [
        *pruebas_roles(),
        *pruebas_parcelas(),
        *pruebas_asignaciones(),
        *pruebas_periodos(),
        *pruebas_emergencia(),
        *pruebas_ventana(),
        *pruebas_permisos_app(),
    ]


# --------------------------------------------------------------------------- ejecución


@dataclass(frozen=True)
class Resultado:
    prueba: Prueba
    obtenido: str
    ok: bool


def describir_esperado(esperado: str) -> str:
    if esperado == PASA:
        return PASA
    if esperado == CUALQUIER_ERROR:
        return "falla"
    return f"falla {esperado}"


def cumple(esperado: str, sqlstate: str | None) -> bool:
    if esperado == PASA:
        return sqlstate is None
    if esperado == CUALQUIER_ERROR:
        return sqlstate is not None
    return sqlstate == esperado


def ejecutar_prueba(conn: psycopg.Connection, prueba: Prueba) -> Resultado:
    """Prepara y ejecuta la prueba en una transacción que siempre se revierte."""
    try:
        with conn.cursor() as cur:
            try:
                contexto = prueba.preparar(cur)
            except psycopg.Error as error:
                return Resultado(prueba, f"error al preparar {error.sqlstate}", False)
            try:
                prueba.accion(cur, contexto)
                sqlstate = None
            except psycopg.Error as error:
                sqlstate = error.sqlstate or "desconocido"
    finally:
        conn.rollback()
    obtenido = PASA if sqlstate is None else f"falla {sqlstate}"
    return Resultado(prueba, obtenido, cumple(prueba.esperado, sqlstate))


def conectar(rol: str) -> psycopg.Connection:
    """Conecta como `rol` con la cadena de su variable de entorno, sin mostrarla nunca."""
    variable = VARIABLES_CONEXION[rol]
    cadena = os.environ.get(variable)
    if not cadena:
        raise SystemExit(
            f"[FALLO] Falta la variable {variable}. Cargue antes: . .\\scripts\\entorno_dev.ps1 -Pruebas"
        )
    try:
        return psycopg.connect(cadena, autocommit=False, connect_timeout=15)
    except psycopg.Error as error:
        mensaje = PATRON_URL.sub("[REDACTADO]", str(error))
        raise SystemExit(f"[FALLO] No se pudo conectar como {rol}: {mensaje}") from None


def quedaron_datos(conn: psycopg.Connection) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) FROM usuarios_usuario WHERE correo LIKE %s",
            (f"prueba-%@{DOMINIO_PRUEBA}",),
        )
        cantidad = cur.fetchone()[0]
    conn.rollback()
    return cantidad > 0


def imprimir_tabla(resultados: list[Resultado]) -> None:
    encabezado = ("id", "descripción", "esperado", "obtenido", "OK/FALLA")
    filas = [
        (
            r.prueba.id,
            r.prueba.descripcion,
            describir_esperado(r.prueba.esperado),
            r.obtenido,
            "OK" if r.ok else "FALLA",
        )
        for r in resultados
    ]
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
        resultados = [ejecutar_prueba(conexiones[p.conexion], p) for p in todas_las_pruebas()]
        imprimir_tabla(resultados)
        correctas = sum(r.ok for r in resultados)
        print(f"\nTotal: {correctas}/{len(resultados)} OK")
        limpio = not quedaron_datos(conexiones[MIGRADOR])
        print("[OK] No quedaron datos de prueba." if limpio else "[FALLO] Quedaron datos de prueba.")
        return 0 if correctas == len(resultados) and limpio else 1
    finally:
        for conn in conexiones.values():
            conn.close()


if __name__ == "__main__":
    sys.exit(main())
