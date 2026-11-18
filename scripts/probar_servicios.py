#!/usr/bin/env python3
"""Pruebas de la capa de servicios de mediciones (O1 a O4) contra la base dev.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_servicios.py

Corre los servicios de mediciones.servicios a través de Django como app_rw (DATABASE_URL_APP). Cada
prueba corre en una transacción que SIEMPRE se revierte: las tablas de mediciones no admiten borrado,
así que nada se confirma. Al final compara los conteos con los iniciales.

Dos pruebas de enmienda necesitan un período cerrado hace semanas, y la base fija cerrado_en = now().
Esas corren como migrador (DATABASE_URL_MIGRADOR), que dentro de la transacción revertida desactiva
solo el disparador que fija la fecha de cierre y quita FORCE de la RLS; los demás disparadores siguen
activos. Nunca imprime cadenas de conexión ni la clave de firma.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "scripts"))

APP = "DATABASE_URL_APP"
MIGRADOR = "DATABASE_URL_MIGRADOR"
PATRON_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")

for _variable in (APP, MIGRADOR):
    if not os.environ.get(_variable):
        raise SystemExit(f"[FALLO] Falta la variable {_variable}. Cargue antes: . .\\scripts\\entorno_dev.ps1 -Pruebas")
os.environ["DATABASE_URL"] = os.environ[APP]
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402

django.setup()

import dj_database_url  # noqa: E402
from django.db import DatabaseError, connection, connections, transaction  # noqa: E402

import probar_mediciones as pm  # noqa: E402
from mediciones import firma, plazos, servicios  # noqa: E402
from mediciones.errores import NoEncontrado, ParametroNoConfigurado, ReglaIncumplida  # noqa: E402
from mediciones.huella import calcular_huella  # noqa: E402
from mediciones.models import Alerta, Aprobacion, Certificado, Enmienda, Medicion, MedicionVersion, Periodo  # noqa: E402
from usuarios.models import Usuario  # noqa: E402

PASA = "pasa"
DOMINIO = "servicios-prueba.test"
NOMBRE_PRUEBA = "Persona de prueba de servicios"
HASH_FICTICIO = "!no-usable"
CO2E_BAJO = Decimal("100.000")
CO2E_ALTO = Decimal("600.000")
CO2E_CORREGIDO = Decimal("150.000")
FECHA = date(2026, 1, 15)
FECHA_CORREGIDA = date(2026, 2, 1)
NOTAS = "Muestreo de prueba"
NOTAS_CORREGIDAS = "Muestreo corregido"
JUSTIFICACION = "Error detectado en el muestreo original"
MOTIVO = "Corrección del valor de muestreo"
INICIO, FIN = date(2099, 1, 1), date(2099, 12, 31)
PLAZO_VERIFICACION_PRUEBA = 15
# Región de parcelas distinta de la de probar_bd.py y probar_mediciones.py.
X0, Y0, LADO = 700000, 1100000, 100
TABLAS_RLS = pm.TABLAS_RLS
TABLAS_CONTEO = [
    "catalogo_finca",
    "catalogo_parcela",
    "catalogo_asignacion",
    "mediciones_periodo",
    "mediciones_politicaparametro",
    "mediciones_medicion",
    "mediciones_medicionversion",
    "mediciones_aprobacion",
    "mediciones_enmienda",
    "mediciones_certificado",
    "mediciones_alerta",
]


class SinEfecto(Exception):
    """La sentencia no afectó filas (por ejemplo, la RLS las filtró sin error)."""


class _Revertir(Exception):
    """Termina la transacción de la prueba con ROLLBACK."""


def _sqlstate(error: DatabaseError) -> str:
    return getattr(error.__cause__, "sqlstate", None) or "?"


def condicion(accion) -> str:
    """Ejecuta la acción en un savepoint y devuelve "pasa", la condición incumplida o el error."""
    try:
        with transaction.atomic():
            accion()
    except ReglaIncumplida as error:
        return error.condicion
    except NoEncontrado:
        return "no encontrado"
    except ParametroNoConfigurado:
        return "sin parámetro"
    except DatabaseError as error:
        return f"falla {_sqlstate(error)}"
    except SinEfecto:
        return "sin efecto"
    except Exception as error:  # cualquier otra excepción se informa por su tipo
        return f"excepción {type(error).__name__}"
    return PASA


def usar(variable: str) -> None:
    """Reconecta la conexión de Django con la cadena de esa variable (sin imprimirla)."""
    conexion = connections["default"]
    conexion.close()
    conexion.settings_dict.update(dj_database_url.parse(os.environ[variable], conn_max_age=0))
    with connection.cursor() as cursor:
        # Ajuste de sesión fuera de toda transacción: un lock con otra sesión falla en 10 s.
        cursor.execute("SET lock_timeout = '10s'")


# --------------------------------------------------------------------------- datos


class Datos:
    """Datos de prueba con la conexión de Django, dentro de la transacción de la prueba."""

    def __init__(self):
        self.parcelas = 0

    @staticmethod
    def sql(sentencia: str, parametros=None) -> None:
        with connection.cursor() as cursor:
            cursor.execute(sentencia, parametros)

    @staticmethod
    def afectar(sentencia: str, parametros) -> None:
        with connection.cursor() as cursor:
            cursor.execute(sentencia, parametros)
            if cursor.rowcount != 1:
                raise SinEfecto()

    def actor(self, usuario) -> None:
        self.sql("SELECT set_config('app.usuario_id', %s, true)", [str(usuario.pk)])

    def usuario(self, *roles: str) -> Usuario:
        usuario_id = uuid.uuid4()
        self.sql(
            "INSERT INTO usuarios_usuario (id, password, correo, nombre, activo, creado_en)"
            " VALUES (%s, %s, %s, %s, true, now())",
            [usuario_id, HASH_FICTICIO, f"s-{usuario_id.hex[:12]}@{DOMINIO}", NOMBRE_PRUEBA],
        )
        for rol in roles:
            self.dar_rol(usuario_id, rol)
        return Usuario.objects.get(pk=usuario_id)

    def dar_rol(self, usuario_id, rol: str) -> None:
        self.sql(
            "INSERT INTO usuarios_rolusuario (id, usuario_id, rol_id, desde) VALUES (%s, %s, %s, now())",
            [uuid.uuid4(), usuario_id, rol],
        )

    def cambiar_rol(self, usuario, anterior: str, nuevo: str) -> None:
        self.afectar(
            "UPDATE usuarios_rolusuario SET hasta = now() WHERE usuario_id = %s AND rol_id = %s AND hasta IS NULL",
            [usuario.pk, anterior],
        )
        self.dar_rol(usuario.pk, nuevo)

    def parcela_asignada(self, tecnico) -> uuid.UUID:
        finca_id = uuid.uuid4()
        self.sql("INSERT INTO catalogo_finca (id, nombre, creada_en) VALUES (%s, %s, now())", [finca_id, "Finca de prueba"])
        x = X0 + self.parcelas * 2 * LADO
        self.parcelas += 1
        wkt = f"POLYGON(({x} {Y0}, {x + LADO} {Y0}, {x + LADO} {Y0 + LADO}, {x} {Y0 + LADO}, {x} {Y0}))"
        parcela_id = uuid.uuid4()
        self.sql(
            "INSERT INTO catalogo_parcela (id, finca_id, codigo, geom) VALUES (%s, %s, %s, ST_GeomFromText(%s, 5367))",
            [parcela_id, finca_id, f"SP-{parcela_id.hex[:8]}", wkt],
        )
        self.sql(
            "INSERT INTO catalogo_asignacion (id, tecnico_id, parcela_id, desde, hasta)"
            " VALUES (%s, %s, %s, now() - interval '1 hour', now() + interval '30 days')",
            [uuid.uuid4(), tecnico.pk, parcela_id],
        )
        return parcela_id

    # flujos con los servicios

    def base(self, co2e=CO2E_BAJO) -> dict:
        """Técnico R1 con parcela asignada, tres R2, dos R7, período abierto y medición en borrador."""
        ctx = {
            "tecnico": self.usuario("R1"),
            "r2": self.usuario("R2"),
            "r2b": self.usuario("R2"),
            "r2c": self.usuario("R2"),
            "r7": self.usuario("R7"),
            "r7b": self.usuario("R7"),
        }
        ctx["parcela"] = self.parcela_asignada(ctx["tecnico"])
        ctx["periodo"] = servicios.abrir_periodo(ctx["r7"], INICIO, FIN).periodo_id
        registro = servicios.registrar_medicion(
            ctx["tecnico"], ctx["parcela"], ctx["periodo"], co2e_toneladas=co2e, fecha_muestreo=FECHA, notas=NOTAS
        )
        ctx["medicion"], ctx["huella"] = registro.medicion_id, registro.huella
        return ctx

    def presentada(self, co2e=CO2E_BAJO) -> dict:
        ctx = self.base(co2e)
        servicios.presentar_medicion(ctx["tecnico"], ctx["medicion"])
        return ctx

    def presentada_y_cerrada(self, co2e=CO2E_BAJO) -> dict:
        ctx = self.presentada(co2e)
        servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
        return ctx

    def certificada(self, co2e=CO2E_BAJO) -> dict:
        ctx = self.presentada_y_cerrada(co2e)
        ctx["certificado"] = servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]).certificado_id
        return ctx

    # lecturas con un actor R7 (ve todas las filas)

    def estado(self, ctx) -> tuple[str, int]:
        self.actor(ctx["r7"])
        return Medicion.objects.filter(pk=ctx["medicion"]).values_list("estado", "ciclo").get()

    def versiones(self, ctx) -> list[MedicionVersion]:
        self.actor(ctx["r7"])
        return list(MedicionVersion.objects.filter(medicion_id=ctx["medicion"]).order_by("numero"))

    def certificados(self, ctx) -> list[Certificado]:
        self.actor(ctx["r7"])
        return list(Certificado.objects.filter(medicion_id=ctx["medicion"]).order_by("emitido_en"))

    def cerrado_en(self, ctx):
        return Periodo.objects.filter(pk=ctx["periodo"]).values_list("cerrado_en", flat=True).get()


def documento(certificado: Certificado) -> dict:
    return {
        "payload": certificado.payload,
        "signature": certificado.firma,
        "public_key": certificado.clave_publica,
        "alg": certificado.alg,
    }


def firma_valida(certificado: Certificado) -> bool:
    return firma.verificar(documento(certificado), firma.huella_publica()).estado == firma.ESTADO_VALIDO


def verify_cert_externo(certificado: Certificado) -> int:
    """Ejecuta scripts/verify_cert.py como lo haría un tercero; el archivo queda fuera del repositorio."""
    with tempfile.TemporaryDirectory() as carpeta:
        archivo = Path(carpeta) / "certificado.json"
        archivo.write_text(json.dumps(documento(certificado)), encoding="utf-8")
        proceso = subprocess.run(
            [sys.executable, str(RAIZ / "scripts" / "verify_cert.py"), str(archivo), "--huella", firma.huella_publica()],
            capture_output=True, text=True, timeout=60,
        )
    return proceso.returncode


def con_ahora(momento):
    return mock.patch.object(servicios, "_ahora", return_value=momento)


def sin_plazo_de_verificacion():
    """Simula que falta el parámetro del plazo de verificación, para comprobar que se falla cerrado."""
    original = plazos.leer_parametro

    def lector(clave):
        if clave == plazos.CLAVE_PLAZO_VERIFICACION:
            raise ParametroNoConfigurado(f"Falta el parámetro de política {clave}.")
        return original(clave)

    return mock.patch.object(plazos, "leer_parametro", side_effect=lector)


def resultado(ok: bool, obtenido: str):
    return ok, obtenido


# --------------------------------------------------------------------------- O1: técnico


def o01():
    d = Datos()
    ctx = d.base()
    v1 = d.versiones(ctx)[0]
    esperada = calcular_huella(ctx["medicion"], 1, CO2E_BAJO, FECHA, NOTAS, ctx["tecnico"].pk, None)
    estado = d.estado(ctx)
    ok = estado == ("borrador", 1) and v1.numero == 1 and ctx["huella"] == v1.huella == esperada
    return resultado(ok, f"{estado[0]}, versión {v1.numero}, huella de la base igual a la calculada={v1.huella == esperada}")


def o02():
    d = Datos()
    ctx = d.base()
    servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    otra = d.parcela_asignada(ctx["tecnico"])
    obtenido = condicion(lambda: servicios.registrar_medicion(
        ctx["tecnico"], otra, ctx["periodo"], co2e_toneladas=CO2E_BAJO, fecha_muestreo=FECHA))
    return resultado(obtenido == "Cd5", obtenido)


def o03():
    d = Datos()
    ctx = d.base()
    r = servicios.modificar_medicion(ctx["tecnico"], ctx["medicion"], co2e_toneladas=CO2E_CORREGIDO,
                                     fecha_muestreo=FECHA, notas=NOTAS)
    v1, v2 = d.versiones(ctx)
    ok = r.version_numero == 2 and v2.huella_previa == v1.huella == ctx["huella"] and v1.co2e_toneladas == CO2E_BAJO
    return resultado(ok, f"versión {r.version_numero}, encadenada={v2.huella_previa == v1.huella}, versión 1 intacta={v1.co2e_toneladas == CO2E_BAJO}")


def o04():
    d = Datos()
    ctx = d.presentada()
    obtenido = condicion(lambda: servicios.modificar_medicion(
        ctx["tecnico"], ctx["medicion"], co2e_toneladas=CO2E_CORREGIDO, fecha_muestreo=FECHA))
    return resultado(obtenido == "Cd6", obtenido)


def o05():
    d = Datos()
    ctx = d.base()
    otro = d.usuario("R1")
    obtenido = condicion(lambda: servicios.modificar_medicion(
        otro, ctx["medicion"], co2e_toneladas=CO2E_CORREGIDO, fecha_muestreo=FECHA))
    return resultado(obtenido == "Cd6", obtenido)


def o06():
    d = Datos()
    ctx = d.base()
    r = servicios.presentar_medicion(ctx["tecnico"], ctx["medicion"])
    ok = r.estado == "presentada" and d.estado(ctx)[0] == "presentada" and r.huella == ctx["huella"]
    return resultado(ok, f"{r.estado}, huella presentada igual a la vigente={r.huella == ctx['huella']}")


def o07():
    d = Datos()
    ctx = d.base()
    servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    obtenido = condicion(lambda: servicios.presentar_medicion(ctx["tecnico"], ctx["medicion"]))
    return resultado(obtenido == "Cd5", f"{obtenido} (medición {d.estado(ctx)[0]})")


# --------------------------------------------------------------------------- O1: verificación


def a01():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    r = servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"])
    certificados = d.certificados(ctx)
    ok = (r.estado == "certificada" and r.certificado_id is not None and len(certificados) == 1
          and certificados[0].pk == r.certificado_id and firma_valida(certificados[0]))
    return resultado(ok, f"{r.estado}, {len(certificados)} certificado, firma.verificar válido={firma_valida(certificados[0])}")


def a02():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    d.cambiar_rol(ctx["tecnico"], "R1", "R2")
    obtenido = condicion(lambda: servicios.aprobar_medicion(ctx["tecnico"], ctx["medicion"], huella_revisada=ctx["huella"]))
    return resultado(obtenido == "Cd8", f"{obtenido} (quien registró, ahora R2)")


def a03():
    d = Datos()
    ctx = d.presentada()
    obtenido = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]))
    return resultado(obtenido == "Cd7", obtenido)


def a04():
    d = Datos()
    ctx = d.base()
    abierto = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]))
    servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    cerrado = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]))
    return resultado(abierto == cerrado == "Cd7", f"borrador {abierto}; sin_presentar {cerrado}")


def a05():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    obtenido = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada="e" * 64))
    return resultado(obtenido == "Cd7", obtenido)


def a06():
    d = Datos()
    ctx = d.certificada()
    obtenido = condicion(lambda: servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=ctx["huella"]))
    return resultado(obtenido == "Cd10", obtenido)


def a07():
    d = Datos()
    ctx = d.presentada_y_cerrada(CO2E_ALTO)
    primera = servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"])
    repetida = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]))
    segunda = servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=ctx["huella"])
    certificados = d.certificados(ctx)
    aprobadores = certificados[0].payload["aprobadores"] if certificados else []
    ok = (primera.estado == "aprobada" and primera.certificado_id is None and repetida == "Cd8"
          and segunda.estado == "certificada" and len(certificados) == 1 and len(aprobadores) == 2)
    return resultado(ok, f"1.a {primera.estado} sin certificado; repetida {repetida}; 2.a {segunda.estado}, "
                         f"{len(aprobadores)} aprobadores en el payload")


def a08():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    primera = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]))
    segunda = condicion(lambda: servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=ctx["huella"]))
    certificados = len(d.certificados(ctx))
    return resultado(primera == PASA and segunda == "Cd10" and certificados == 1,
                     f"1.a {primera}, 2.a {segunda}, certificados={certificados} (variante secuencial)")


def a09():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    with mock.patch.object(firma, "firmar", side_effect=RuntimeError("firma no disponible")):
        obtenido = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]))
    d.actor(ctx["r7"])
    aprobaciones = Aprobacion.objects.filter(medicion_id=ctx["medicion"]).count()
    certificados = len(d.certificados(ctx))
    estado = d.estado(ctx)[0]
    ok = obtenido == "excepción RuntimeError" and aprobaciones == 0 and certificados == 0 and estado == "presentada"
    return resultado(ok, f"{obtenido}; aprobaciones={aprobaciones}, certificados={certificados}, {estado}")


def dv01():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    r = servicios.devolver_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"])
    return resultado(r.estado == "devuelta" and d.estado(ctx)[0] == "devuelta", r.estado)


def dv02():
    d = Datos()
    ctx = d.presentada()
    obtenido = condicion(lambda: servicios.devolver_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]))
    return resultado(obtenido == "Cd7", obtenido)


def asignar_directo(d: Datos, ctx, verificador) -> None:
    d.actor(ctx["r7"])
    d.afectar("UPDATE mediciones_medicion SET verificador_asignado_id = %s WHERE id = %s", [verificador.pk, ctx["medicion"]])


def r01():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    d.cambiar_rol(ctx["tecnico"], "R1", "R2")
    asignar_directo(d, ctx, ctx["tecnico"])
    r = servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r2"].pk)
    return resultado(r.causa == servicios.CAUSA_CD8, f"pasa ({r.causa})")


def r02():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    inicial = servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r2"].pk)
    with con_ahora(d.cerrado_en(ctx) + timedelta(days=3)):
        obtenido = condicion(lambda: servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r2b"].pk))
    return resultado(inicial.causa == servicios.CAUSA_SIN_ASIGNAR and obtenido == "Cd19",
                     f"asignación inicial {inicial.causa}; a los 3 días {obtenido}")


def r03():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r2"].pk)
    with con_ahora(d.cerrado_en(ctx) + timedelta(days=30)):
        r = servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r2b"].pk)
    return resultado(r.causa == servicios.CAUSA_PLAZO, f"pasa ({r.causa})")


def r04():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r2"].pk)
    with sin_plazo_de_verificacion(), con_ahora(d.cerrado_en(ctx) + timedelta(days=30)):
        obtenido = condicion(lambda: servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r2b"].pk))
    return resultado(obtenido == "sin parámetro", obtenido)


def r08():
    valor = plazos.leer_parametro(plazos.CLAVE_PLAZO_VERIFICACION)
    return resultado(valor == Decimal(PLAZO_VERIFICACION_PRUEBA), f"{plazos.CLAVE_PLAZO_VERIFICACION} = {valor}")


def r05():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    d.cambiar_rol(ctx["tecnico"], "R1", "R2")
    obtenido = condicion(lambda: servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["tecnico"].pk))
    return resultado(obtenido == "Cd8", f"{obtenido} (destino: quien registró, ahora R2)")


def r06():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    obtenido = condicion(lambda: servicios.reasignar_verificacion(ctx["r7"], ctx["medicion"], ctx["r7b"].pk))
    return resultado(obtenido == "Cd19", obtenido)


def r07():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    obtenidos = []
    for actor in (ctx["r2"], ctx["tecnico"]):
        d.actor(actor)
        obtenidos.append(condicion(lambda: d.afectar(
            "UPDATE mediciones_medicion SET verificador_asignado_id = %s WHERE id = %s", [ctx["r2b"].pk, ctx["medicion"]])))
    d.actor(ctx["r7"])
    columna = condicion(lambda: d.afectar("UPDATE mediciones_medicion SET creada_en = now() WHERE id = %s", [ctx["medicion"]]))
    ok = obtenidos[0] == "falla 23000" and obtenidos[1] in ("falla 23000", "sin efecto") and columna == "falla 42501"
    return resultado(ok, f"R2 {obtenidos[0]}, R1 registrante {obtenidos[1]}, otra columna {columna}")


# --------------------------------------------------------------------------- O2: períodos


def pe01():
    d = Datos()
    r7 = d.usuario("R7")
    r = servicios.abrir_periodo(r7, INICIO, FIN)
    return resultado(r.estado == "abierto" and r.cerrado_en is None, r.estado)


def pe02():
    d = Datos()
    ctx = d.base()
    r = servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    cerrado_por = Periodo.objects.filter(pk=ctx["periodo"]).values_list("cerrado_por_id", flat=True).get()
    ok = r.estado == "cerrado" and r.cerrado_en is not None and cerrado_por == ctx["r7"].pk
    return resultado(ok, f"{r.estado}, fecha y autor fijados por la base={ok}")


def pe03():
    d = Datos()
    ctx = d.base()
    servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    obtenido = condicion(lambda: servicios.cerrar_periodo(ctx["r7"], ctx["periodo"]))
    return resultado(obtenido == "Cd5", obtenido)


def pe04():
    d = Datos()
    ctx = d.base()
    otra = d.parcela_asignada(ctx["tecnico"])
    presentada = servicios.registrar_medicion(ctx["tecnico"], otra, ctx["periodo"], co2e_toneladas=CO2E_BAJO, fecha_muestreo=FECHA)
    servicios.presentar_medicion(ctx["tecnico"], presentada.medicion_id)
    r = servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    estados = (d.estado(ctx)[0], d.estado({**ctx, "medicion": presentada.medicion_id})[0])
    ok = r.sin_presentar == 1 and r.en_verificacion == 1 and estados == ("sin_presentar", "presentada")
    return resultado(ok, f"sin_presentar={r.sin_presentar}, en verificación={r.en_verificacion}")


def pe05():
    d = Datos()
    r2 = d.usuario("R2")
    obtenido = condicion(lambda: servicios.abrir_periodo(r2, INICIO, FIN))
    return resultado(obtenido == "falla 23000", f"{obtenido} (la base exige R7)")


# --------------------------------------------------------------------------- O3: certificados


def n01():
    d = Datos()
    ctx = d.certificada()
    r = servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=JUSTIFICACION)
    d.actor(ctx["r7"])
    vigentes = Certificado.objects.filter(parcela_id=ctx["parcela"], periodo_id=ctx["periodo"], estado="vigente").count()
    avisos = Alerta.objects.filter(tipo=servicios.TIPO_AVISO_ANULACION, prioridad="prioritaria",
                                   detalle__certificado_id=str(ctx["certificado"])).count()
    ok = (r.estado == "anulado" and (r.medicion_estado, r.ciclo) == ("presentada", 2) and vigentes == 0 and avisos == 1)
    return resultado(ok, f"{r.estado}; medición {r.medicion_estado} ciclo {r.ciclo}; vigentes={vigentes}; avisos={avisos}")


def n02():
    d = Datos()
    ctx = d.certificada()
    obtenido = condicion(lambda: servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion="   "))
    return resultado(obtenido == "Cd20", obtenido)


def n03():
    d = Datos()
    ctx = d.certificada()
    with mock.patch.object(servicios, "_registrar_aviso_gerencia", side_effect=RuntimeError("aviso no registrado")):
        obtenido = condicion(lambda: servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=JUSTIFICACION))
    estado_certificado = d.certificados(ctx)[0].estado
    estado = d.estado(ctx)
    ok = obtenido == "excepción RuntimeError" and estado_certificado == "vigente" and estado == ("certificada", 1)
    return resultado(ok, f"{obtenido}; certificado {estado_certificado}; medición {estado[0]}")


def n04():
    d = Datos()
    ctx = d.certificada()
    servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=JUSTIFICACION)
    r = servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=ctx["huella"])
    certificados = d.certificados(ctx)
    estados = [c.estado for c in certificados]
    ok = (r.certificado_id not in (None, ctx["certificado"]) and estados == ["anulado", "vigente"]
          and certificados[1].ciclo == 2 and firma_valida(certificados[1]))
    return resultado(ok, f"{r.estado}; certificados {estados}; ciclo del nuevo {certificados[-1].ciclo}")


def x01():
    d = Datos()
    ctx = d.certificada()
    primera = servicios.exportar_certificado(ctx["r7"], ctx["certificado"])
    segunda = servicios.exportar_certificado(ctx["r7"], ctx["certificado"])
    datos = json.loads(primera.contenido)
    etapas = [e["etapa"] for e in datos["trazabilidad"]]
    actores = {e["actor"] for e in datos["trazabilidad"]} - {None}
    texto = primera.contenido.decode("utf-8")
    personas = [str(ctx[k].pk) for k in ("tecnico", "r2", "r7")]
    sin_nombres = NOMBRE_PRUEBA not in texto and DOMINIO not in texto and not any(p in texto for p in personas)
    emisor = datos["trazabilidad"][etapas.index("emision")]["actor"]
    ok = (primera.contenido == segunda.contenido
          and primera.huella_sha256 == hashlib.sha256(primera.contenido).hexdigest()
          and etapas == ["registro", "presentacion", "aprobacion", "emision"]
          and all(re.fullmatch(r"[0-9a-f]{16}", a) for a in actores) and sin_nombres
          and emisor == firma.seudonimo(ctx["r2"].pk)
          and firma.verificar(datos["certificado"], firma.huella_publica()).estado == firma.ESTADO_VALIDO)
    return resultado(ok, f"estable={primera.contenido == segunda.contenido}, etapas={etapas}, sin nombres={sin_nombres}")


def x02():
    d = Datos()
    ctx = d.certificada()
    antes = servicios.exportar_certificado(ctx["r7"], ctx["certificado"])
    servicios.anular_certificado(ctx["r7b"], ctx["certificado"], justificacion=JUSTIFICACION)
    despues = json.loads(servicios.exportar_certificado(ctx["r7"], ctx["certificado"]).contenido)
    etapas = [e["etapa"] for e in despues["trazabilidad"]]
    ok = (etapas[-1] == "anulacion" and despues["estado"] == "anulado"
          and despues["certificado"] == json.loads(antes.contenido)["certificado"])
    return resultado(ok, f"estado {despues['estado']}, última etapa {etapas[-1]}, documento firmado sin cambios")


# --------------------------------------------------------------------------- O4: enmiendas


def solicitar(ctx, solicitante=None, co2e=CO2E_CORREGIDO):
    return servicios.solicitar_enmienda(
        solicitante or ctx["tecnico"], ctx["medicion"], motivo=MOTIVO, co2e_nuevo=co2e,
        fecha_nueva=FECHA_CORREGIDA, notas_nuevas=NOTAS_CORREGIDAS,
    )


def e01():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    with con_ahora(d.cerrado_en(ctx) + timedelta(days=10)):
        r = solicitar(ctx)
    d.actor(ctx["r7"])
    base = Enmienda.objects.filter(pk=r.enmienda_id).values_list("version_base__huella", flat=True).get()
    return resultado(r.estado == "solicitada" and base == ctx["huella"], f"{r.estado}, valor anterior = versión vigente={base == ctx['huella']}")


def e02():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    with con_ahora(d.cerrado_en(ctx) + timedelta(days=120)):
        obtenido = condicion(lambda: solicitar(ctx))
    return resultado(obtenido == "Cd11", obtenido)


def e03():
    d = Datos()
    ctx = d.certificada()
    servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=JUSTIFICACION)
    with con_ahora(d.cerrado_en(ctx) + timedelta(days=120)):
        obtenido = condicion(lambda: solicitar(ctx))
    return resultado(obtenido == PASA, obtenido)


def e04():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    enmienda = solicitar(ctx)
    r = servicios.resolver_enmienda(ctx["r7"], enmienda.enmienda_id, autorizar=True)
    v2 = d.versiones(ctx)[-1]
    valores = (v2.co2e_toneladas, v2.fecha_muestreo, v2.notas, v2.creada_por_id, v2.enmienda_id)
    esperados = (CO2E_CORREGIDO, FECHA_CORREGIDA, NOTAS_CORREGIDAS, ctx["tecnico"].pk, enmienda.enmienda_id)
    ok = r.estado == "autorizada" and r.version_numero == 2 and valores == esperados and r.medicion_estado == "presentada"
    return resultado(ok, f"{r.estado}, versión {r.version_numero} con los valores pedidos={valores == esperados}, {r.medicion_estado}")


def e05():
    d = Datos()
    ctx = d.certificada()
    enmienda = solicitar(ctx)
    d.cambiar_rol(ctx["r2"], "R2", "R7")
    obtenido = condicion(lambda: servicios.resolver_enmienda(ctx["r2"], enmienda.enmienda_id, autorizar=True))
    return resultado(obtenido == "Cd12", f"{obtenido} (aprobador original, ahora R7)")


def e08():
    d = Datos()
    ctx = d.presentada_y_cerrada()
    enmienda = solicitar(ctx)
    antes = (d.estado(ctx), len(d.versiones(ctx)))
    r = servicios.resolver_enmienda(ctx["r7"], enmienda.enmienda_id, autorizar=False)
    despues = (d.estado(ctx), len(d.versiones(ctx)))
    return resultado(r.estado == "rechazada" and antes == despues, f"{r.estado}; medición sin cambios={antes == despues}")


def e09():
    d = Datos()
    ctx = d.presentada_y_cerrada(CO2E_ALTO)
    primera = servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"])
    enmienda = solicitar(ctx, co2e=Decimal("550.000"))
    r = servicios.resolver_enmienda(ctx["r7"], enmienda.enmienda_id, autorizar=True)
    nueva = d.versiones(ctx)[-1].huella
    repetida = condicion(lambda: servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=nueva))
    vieja = condicion(lambda: servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=ctx["huella"]))
    segunda = servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=nueva)
    tercera = servicios.aprobar_medicion(ctx["r2c"], ctx["medicion"], huella_revisada=nueva)
    certificado = d.certificados(ctx)[0]
    ok = (primera.estado == "aprobada" and (r.medicion_estado, r.ciclo, r.version_numero) == ("presentada", 1, 2)
          and repetida == "Cd8" and vieja == "Cd7" and segunda.certificado_id is None and segunda.aprobaciones == 1
          and tercera.estado == "certificada" and certificado.payload["medicion_numero"] == 2
          and len(certificado.payload["aprobadores"]) == 2)
    return resultado(ok, f"autorizada: {r.medicion_estado}, ciclo {r.ciclo}, versión {r.version_numero}; aprobador previo {repetida}; "
                         f"huella vieja {vieja}; nueva secuencia {segunda.aprobaciones}/2 y luego {tercera.estado}")


def e10():
    d = Datos()
    ctx = d.certificada()
    enmienda = solicitar(ctx)
    r = servicios.resolver_enmienda(ctx["r7"], enmienda.enmienda_id, autorizar=True)
    nueva = d.versiones(ctx)[-1].huella
    bloqueada = condicion(lambda: servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=nueva))
    anulacion = servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=JUSTIFICACION)
    final = servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=nueva)
    vigente = [c for c in d.certificados(ctx) if c.estado == "vigente"]
    ok = (r.medicion_estado == "certificada" and bloqueada == "Cd10" and anulacion.ciclo == 2
          and final.estado == "certificada" and len(vigente) == 1 and vigente[0].payload["medicion_numero"] == 2)
    return resultado(ok, f"tras autorizar {r.medicion_estado}; aprobar {bloqueada}; tras anular ciclo {anulacion.ciclo} y {final.estado} con la versión 2")


# --------------------------------------------------------------------------- enmiendas con cierre en el pasado (migrador)


def como_dueno(d: Datos) -> None:
    """Como migrador y dentro de la transacción revertida: desactiva solo el disparador que fija
    cerrado_en y quita FORCE para operar como dueño. Los demás disparadores siguen activos.
    """
    d.sql("ALTER TABLE mediciones_periodo DISABLE TRIGGER mediciones_periodo_inmutable")
    for tabla in TABLAS_RLS:
        d.sql(f"ALTER TABLE {tabla} NO FORCE ROW LEVEL SECURITY")


def cierre_en_el_pasado(d: Datos, ctx, dias: int) -> None:
    """Cierra el período `dias` días atrás; el disparador que pasa los borradores a sin_presentar
    y las reglas de enmienda siguen activos.
    """
    d.afectar(
        "UPDATE mediciones_periodo SET estado = 'cerrado', cerrado_en = now() - make_interval(days => %s),"
        " cerrado_por_id = %s WHERE id = %s",
        [dias, ctx["r7"].pk, ctx["periodo"]],
    )


def e06():
    d = Datos()
    como_dueno(d)
    ctx = d.presentada()
    cierre_en_el_pasado(d, ctx, 120)
    primero = servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]).certificado_id
    servicios.anular_certificado(ctx["r7"], primero, justificacion=JUSTIFICACION)
    enmienda = solicitar(ctx)
    segundo = servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=ctx["huella"])
    obtenido = condicion(lambda: servicios.resolver_enmienda(ctx["r7b"], enmienda.enmienda_id, autorizar=True))
    return resultado(segundo.estado == "certificada" and obtenido == "Cd12",
                     f"solicitada a los 120 días con un certificado anulado; nuevo certificado vigente; autorizar {obtenido}")


def e07():
    d = Datos()
    como_dueno(d)
    ctx = d.presentada()
    cierre_en_el_pasado(d, ctx, 89)
    enmienda = solicitar(ctx)
    with con_ahora(d.cerrado_en(ctx) + timedelta(days=91)):
        r = servicios.resolver_enmienda(ctx["r7"], enmienda.enmienda_id, autorizar=True)
    return resultado(r.estado == "autorizada" and r.version_numero == 2, f"solicitada a los 89 días, autorizada a los 91: {r.estado}")


# --------------------------------------------------------------------------- flujo completo


def f01():
    d = Datos()
    tecnico, r2, r2b, r7 = d.usuario("R1"), d.usuario("R2"), d.usuario("R2"), d.usuario("R7")
    parcela = d.parcela_asignada(tecnico)
    periodo = servicios.abrir_periodo(r7, INICIO, FIN).periodo_id
    medicion = servicios.registrar_medicion(tecnico, parcela, periodo, co2e_toneladas=CO2E_BAJO, fecha_muestreo=FECHA).medicion_id
    servicios.modificar_medicion(tecnico, medicion, co2e_toneladas=CO2E_CORREGIDO, fecha_muestreo=FECHA, notas=NOTAS)
    huella = servicios.presentar_medicion(tecnico, medicion).huella
    servicios.cerrar_periodo(r7, periodo)
    primero = servicios.aprobar_medicion(r2, medicion, huella_revisada=huella).certificado_id
    d.actor(r7)
    salida_1 = verify_cert_externo(Certificado.objects.get(pk=primero))
    exportado = servicios.exportar_certificado(r7, primero)
    servicios.anular_certificado(r7, primero, justificacion=JUSTIFICACION)
    segundo = servicios.aprobar_medicion(r2b, medicion, huella_revisada=huella).certificado_id
    d.actor(r7)
    salida_2 = verify_cert_externo(Certificado.objects.get(pk=segundo))
    estados = dict(Certificado.objects.filter(medicion_id=medicion).values_list("id", "estado"))
    ok = (salida_1 == 0 and salida_2 == 0 and len(exportado.huella_sha256) == 64 and segundo != primero
          and estados == {primero: "anulado", segundo: "vigente"})
    return resultado(ok, f"verify_cert exit {salida_1} y {salida_2}; exportado; certificados {sorted(estados.values())}")


# --------------------------------------------------------------------------- ejecución

PRUEBAS = [
    ("O01", "Registrar con período abierto", "borrador, versión 1", o01, False),
    ("O02", "Registrar con período cerrado", "Cd5", o02, False),
    ("O03", "Modificar borrador propio", "versión 2 encadenada", o03, False),
    ("O04", "Modificar medición presentada", "Cd6", o04, False),
    ("O05", "Modificar medición de otro autor", "Cd6", o05, False),
    ("O06", "Presentar borrador propio", "presentada", o06, False),
    ("O07", "Presentar con período cerrado", "Cd5", o07, False),
    ("A01", "Aprobar con período cerrado y verificador distinto", "certificada, firma válida", a01, False),
    ("A02", "Aprobar la propia", "Cd8", a02, False),
    ("A03", "Aprobar con período abierto", "Cd7", a03, False),
    ("A04", "Aprobar borrador o sin_presentar", "Cd7, Cd7", a04, False),
    ("A05", "Aprobar con huella distinta", "Cd7", a05, False),
    ("A06", "Aprobar con certificado vigente previo", "Cd10", a06, False),
    ("A07", "Más de Valto: 1.a sin emisión, repetida, 2.a distinta", "aprobada; Cd8; certificada", a07, False),
    ("A08", "Dos aprobaciones de la misma medición", "un solo certificado; Cd10", a08, False),
    ("A09", "Falla la firma al emitir", "sin aprobación ni certificado", a09, False),
    ("D01", "Devolver con período cerrado", "devuelta", dv01, False),
    ("D02", "Devolver con período abierto", "Cd7", dv02, False),
    ("R01", "Reasignar: el asignado es quien registró", "pasa (Cd8 del asignado)", r01, False),
    ("R02", "Reasignar con verificador apto y plazo vigente", "Cd19", r02, False),
    ("R03", "Reasignar con plazo vencido", "pasa (plazo)", r03, False),
    ("R04", "Reasignar por plazo con el parámetro ausente (simulado)", "sin parámetro", r04, False),
    ("R05", "Reasignar a quien registró", "Cd8", r05, False),
    ("R06", "Reasignar a un destino sin R2", "Cd19", r06, False),
    ("R07", "Columna verificador_asignado solo la cambia R7", "23000; 23000 o sin efecto; 42501", r07, False),
    ("R08", "Parámetro tver_dias_habiles sembrado", "15", r08, False),
    ("PE01", "Abrir período", "abierto", pe01, False),
    ("PE02", "Cerrar período", "cerrado con fecha y autor", pe02, False),
    ("PE03", "Cerrar un período ya cerrado", "Cd5", pe03, False),
    ("PE04", "Al cerrar, borradores sin presentar y presentadas en cola", "1 y 1", pe04, False),
    ("PE05", "Abrir período sin R7", "falla 23000", pe05, False),
    ("N01", "Anular certificado vigente", "anulado, presentada ciclo 2, aviso", n01, False),
    ("N02", "Anular sin justificación", "Cd20", n02, False),
    ("N03", "Anular con el aviso a gerencia fallando", "no anula", n03, False),
    ("N04", "Tras anular, nueva aprobación completa", "certificado distinto", n04, False),
    ("X01", "Exportar certificado", "estable, SHA-256, sin nombres", x01, False),
    ("X02", "Exportar certificado anulado", "con etapa de anulación", x02, False),
    ("E01", "Enmienda a los 10 días", "solicitada", e01, False),
    ("E02", "Enmienda a los 120 días", "Cd11", e02, False),
    ("E03", "Enmienda a los 120 días con certificado anulado", PASA, e03, False),
    ("E04", "Autorizar con personas distintas", "autorizada, versión 2", e04, False),
    ("E05", "Autorizador igual al aprobador original", "Cd12", e05, False),
    ("E06", "Solicitada fuera de 90 días con certificado vigente", "Cd12", e06, True),
    ("E07", "Solicitada a 89 días y autorizada a 91", "autorizada", e07, True),
    ("E08", "Rechazar no cambia la medición", "rechazada, sin cambios", e08, False),
    ("E09", "Autorizar reinicia la secuencia de aprobación", "nueva versión, presentada", e09, False),
    ("E10", "Enmienda con certificado vigente", "Cd10 hasta anular", e10, False),
    ("F01", "Flujo completo de extremo a extremo", "verify_cert exit 0 dos veces", f01, False),
]


def ejecutar(id_: str, descripcion: str, esperado: str, funcion) -> pm.Resultado:
    salida = None
    try:
        with transaction.atomic():
            salida = funcion()
            raise _Revertir()
    except _Revertir:
        ok, obtenido = salida
        return pm.Resultado(id_, descripcion, esperado, obtenido, ok)
    except ReglaIncumplida as error:
        return pm.Resultado(id_, descripcion, esperado, f"ReglaIncumplida {error.condicion} inesperada", False)
    except DatabaseError as error:
        causa = error.__cause__
        mensaje = getattr(getattr(causa, "diag", None), "message_primary", None) or ""
        detalle = PATRON_URL.sub("[REDACTADO]", mensaje[:90])
        return pm.Resultado(id_, descripcion, esperado, f"excepción {_sqlstate(error)}: {detalle}", False)
    except Exception as error:  # cualquier otra excepción es un fallo de la prueba
        return pm.Resultado(id_, descripcion, esperado, f"excepción {type(error).__name__}", False)


def conteos() -> dict[str, int]:
    """Conteos reales con un actor R7 temporal (ve todas las filas); la transacción se revierte."""
    totales = {}
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                for tabla in ("usuarios_usuario", "usuarios_rolusuario"):
                    cursor.execute(f"SELECT count(*) FROM {tabla}")
                    totales[tabla] = cursor.fetchone()[0]
                d = Datos()
                d.actor(d.usuario("R7"))
                for tabla in TABLAS_CONTEO:
                    cursor.execute(f"SELECT count(*) FROM {tabla}")
                    totales[tabla] = cursor.fetchone()[0]
            raise _Revertir()
    except _Revertir:
        pass
    return totales


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    try:
        usar(APP)
        iniciales = conteos()
        resultados = []
        for id_, descripcion, esperado, funcion, como_migrador in PRUEBAS:
            if como_migrador:
                usar(MIGRADOR)
            try:
                resultados.append(ejecutar(id_, descripcion, esperado, funcion))
            finally:
                if como_migrador:
                    usar(APP)
        finales = conteos()
    except DatabaseError as error:
        raise SystemExit(f"[FALLO] Error de base de datos {_sqlstate(error)}") from None
    finally:
        connections["default"].close()
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
