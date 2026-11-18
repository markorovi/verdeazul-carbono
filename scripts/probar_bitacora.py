#!/usr/bin/env python3
"""Pruebas de punta a punta del servicio de bitácora, su cliente, el verificador y los eventos del PEP.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_bitacora.py

Arranca el servicio en loopback y en un puerto libre, con sal y llave de firma efímeras (solo en
memoria), almacén WORM local en un directorio temporal y dos esquemas temporales de la base de
bitácora que crea y destruye la cuenta propietaria (bit_migrador): la tabla es de solo anexar y sus
filas no se pueden borrar. El servicio se conecta como bit_rw. Las pruebas del negocio corren con
el patrón de siempre (transacción revertida y conteos comparados). Imprime solo resultados,
totales y conteos.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import timedelta
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

if os.environ.get("ENTORNO") != "local" or "VERDEAZUL_PROD" in os.environ:
    raise SystemExit("[FALLO] Solo corre con ENTORNO=local y sin VERDEAZUL_PROD.")
for _variable in ("DATABASE_URL_BITACORA", "DATABASE_URL_BITACORA_MIGRADOR"):
    if not os.environ.get(_variable):
        raise SystemExit(f"[FALLO] Falta {_variable}. Cargue antes: . .\\scripts\\entorno_dev.ps1 -Pruebas")

import probar_autorizacion as pa  # noqa: E402  (configura Django y la conexión de app_rw)

import psycopg  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.core.management.base import CommandError  # noqa: E402
from django.test import override_settings  # noqa: E402

import probar_mediciones as pm  # noqa: E402
import probar_servicios as ps  # noqa: E402
from autorizacion import cliente_bitacora, pdp, pep  # noqa: E402
from autorizacion.cliente_bitacora import ClienteBitacora  # noqa: E402
from autorizacion.pip import Objeto  # noqa: E402
from bitacora_svc import almacen, claves, contrato, esquema, puntos  # noqa: E402
from bitacora_svc.app import crear_aplicacion  # noqa: E402
from bitacora_svc.servicio import Configuracion  # noqa: E402
from bitacora_svc.servidor import ServidorLocal  # noqa: E402
from mediciones.models import Alerta  # noqa: E402
from mediciones.transaccion import hora_de_la_base  # noqa: E402
from usuarios import autenticacion  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
URL_RW = os.environ["DATABASE_URL_BITACORA"]
URL_DUENO = os.environ["DATABASE_URL_BITACORA_MIGRADOR"]
PASA = ps.PASA
CADA = 25
HILOS, POR_HILO = 4, 25


class _Memoria(logging.Handler):
    def __init__(self):
        super().__init__(logging.INFO)
        self.lineas: list[str] = []

    def emit(self, registro):
        self.lineas.append(registro.getMessage())


class Instancia:
    """Un servicio de bitácora sobre su propio esquema temporal, con llaves y almacén propios."""

    def __init__(self, esquema_nombre: str):
        self.esquema = esquema_nombre
        self.sal = os.urandom(32)
        self.llave = Ed25519PrivateKey.generate()
        self.worm = Path(tempfile.mkdtemp(prefix="bitacora_worm_"))
        esquema.aplicar(URL_DUENO, esquema_nombre)
        self.configuracion = Configuracion(url_base=URL_RW, sal=self.sal, llave=self.llave,
                                           almacen=almacen.AlmacenLocal(self.worm), esquema=esquema_nombre, punto_cada=CADA)
        self.app = crear_aplicacion(self.configuracion)
        self.servidor = ServidorLocal(self.app).iniciar()
        self.url = self.servidor.url
        self.cliente = ClienteBitacora(self.url)

    def detener(self):
        self.servidor.detener()

    def reiniciar(self):
        self.servidor = ServidorLocal(self.app, self.servidor.puerto).iniciar()

    def cerrar(self):
        try:
            self.servidor.detener()
        except Exception:
            pass
        esquema.destruir_prueba(URL_DUENO, self.esquema)
        shutil.rmtree(self.worm, ignore_errors=True)


A: Instancia | None = None
B: Instancia | None = None
REGISTRO = _Memoria()
LATENCIA: dict = {}


def evento(**campos) -> dict:
    return {"accion": "intento", "origen": "pep", "resultado": "concedido", "operacion": "O1.Ap", **campos}


def pedir(url: str, metodo: str = "GET", cuerpo: bytes | None = None, timeout: float = 10) -> tuple[int, bytes]:
    solicitud = urllib.request.Request(url, data=cuerpo, method=metodo, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(solicitud, timeout=timeout) as respuesta:
            return respuesta.status, respuesta.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def exportar(instancia: Instancia, carpeta: Path) -> Path:
    archivo = carpeta / "eventos.jsonl"
    archivo.write_bytes(instancia.cliente.exportar())
    return archivo


def verificar_script(eventos: Path, carpeta_puntos: Path, huella: str) -> int:
    proceso = subprocess.run(
        [sys.executable, str(RAIZ / "scripts" / "verify_bitacora.py"), "--eventos", str(eventos),
         "--puntos", str(carpeta_puntos), "--huella", huella, "--cada", str(CADA)],
        capture_output=True, text=True, timeout=120,
    )
    return proceso.returncode


def conteo_tablas(instancia: Instancia) -> tuple[int, int]:
    with psycopg.connect(URL_RW, connect_timeout=15) as conexion:
        return conexion.execute(
            f"SELECT (SELECT count(*) FROM {instancia.esquema}.evento), (SELECT count(*) FROM {instancia.esquema}.punto)"
        ).fetchone()


def con_dueno(sentencias: list[str], confirmar: bool = False) -> list[str]:
    """Ejecuta como propietario; devuelve "pasa" o el SQLSTATE de cada sentencia. Revierte salvo confirmar."""
    resultados = []
    with psycopg.connect(URL_DUENO, connect_timeout=15) as conexion:
        for sentencia in sentencias:
            try:
                with conexion.transaction():
                    conexion.execute(sentencia)
                resultados.append(PASA)
            except psycopg.Error as error:
                resultados.append(f"falla {error.sqlstate}")
        if confirmar:
            conexion.commit()
        else:
            conexion.rollback()
    return resultados


# --------------------------------------------------------------------------- servicio y cadena


def b01():
    inicio = time.monotonic()
    respuestas = [A.cliente.registrar(evento(operacion=op)) for op in ("O1.Rg", "O2.Ci", "O1.Ap")]
    LATENCIA["anexo_medio_s"] = round((time.monotonic() - inicio) / 3, 3)
    exportados = [json.loads(l) for l in A.cliente.exportar().splitlines()]
    reproducidos = all(contrato.hash_de_evento(e) == e["hash"] for e in exportados)
    contiguos = [e["seq"] for e in exportados] == list(range(1, len(exportados) + 1))
    monotono = all(a["sello"] <= b["sello"] for a, b in zip(exportados, exportados[1:]))
    enlazados = all(b["hash_previo"] == a["hash"] for a, b in zip(exportados, exportados[1:])) and exportados[0]["hash_previo"] == contrato.CEROS
    ok = reproducidos and contiguos and monotono and enlazados and [r["seq"] for r in respuestas] == [1, 2, 3]
    return ok, f"hash reproducido={reproducidos}, seq contiguo={contiguos}, sello monótono={monotono}, enlazado={enlazados}"


def b02():
    falso = evento(seq=999, sello="2000-01-01T00:00:00.000000Z", fecha="2000-01-01", hash="f" * 64,
                   hash_previo="e" * 64, clase="consulta", usuario="0" * 32)
    respuesta = A.cliente.registrar(falso)
    guardado = A.cliente.consultar(desde=respuesta["seq"], hasta=respuesta["seq"])[0]
    ok = (respuesta["seq"] == 4 and respuesta["hash"] != "f" * 64 and guardado["sello"] != falso["sello"]
          and guardado["clase"] == "certificacion" and "fecha" not in guardado and "usuario" not in guardado
          and guardado["hash_previo"] != "e" * 64)
    return ok, f"seq asignado {respuesta['seq']}; hash, sello, clase y usuario del cliente descartados={ok}"


def b03():
    base = A.url + "/eventos"
    casos = {
        "campo desconocido": pedir(base, "POST", json.dumps(evento(otro="x")).encode())[0],
        "tipo incorrecto": pedir(base, "POST", json.dumps(evento(operacion=5)).encode())[0],
        "cuerpo excesivo": pedir(base, "POST", json.dumps(evento(notas="x" * 20000)).encode())[0],
        "no JSON": pedir(base, "POST", b"{no json")[0],
        "ruta desconocida": pedir(A.url + "/borrar")[0],
        "método no permitido": pedir(base, "DELETE")[0],
        "PUT en salud": pedir(A.url + "/salud", "PUT", b"{}")[0],
    }
    esperados = {"campo desconocido": 400, "tipo incorrecto": 400, "cuerpo excesivo": 413, "no JSON": 400,
                 "ruta desconocida": 404, "método no permitido": 405, "PUT en salud": 405}
    return casos == esperados, ", ".join(f"{k} {v}" for k, v in casos.items())


def b04():
    seqs: list[int] = []
    errores: list[str] = []
    candado = threading.Lock()

    def trabajar(n):
        # Timeout amplio: aquí se prueba la integridad de la cadena con anexos simultáneos, no la
        # latencia (el cliente del PEP usa 2 s y deniega si se vence).
        for i in range(POR_HILO):
            try:
                estado, cuerpo = pedir(A.url + "/eventos", "POST",
                                       json.dumps(evento(operacion="O1.Ap", servicio=f"hilo_{'abcd'[n]}")).encode(), timeout=60)
                if estado != 201:
                    raise RuntimeError(f"HTTP {estado}")
                with candado:
                    seqs.append(json.loads(cuerpo)["seq"])
            except Exception as error:
                with candado:
                    errores.append(type(error).__name__)

    hilos = [threading.Thread(target=trabajar, args=(n,)) for n in range(HILOS)]
    inicio = time.monotonic()
    for hilo in hilos:
        hilo.start()
    for hilo in hilos:
        hilo.join()
    LATENCIA["concurrencia_s"] = round(time.monotonic() - inicio, 1)
    sin_duplicados = len(seqs) == len(set(seqs)) == HILOS * POR_HILO
    contiguos = sorted(seqs) == list(range(min(seqs), min(seqs) + len(seqs))) if seqs else False
    resumen = A.cliente.verificar()
    ok = not errores and sin_duplicados and contiguos and resumen["codigo"] == 0
    return ok, f"{len(seqs)} eventos en {HILOS} hilos; sin duplicados={sin_duplicados}, contiguos={contiguos}, verificación {resumen['codigo']}"


def b05():
    tabla = f"{A.esquema}.evento"
    obtenidos = {}
    with psycopg.connect(URL_RW, connect_timeout=15) as conexion:
        for nombre, sentencia in (("UPDATE", f"UPDATE {tabla} SET clase = clase"), ("DELETE", f"DELETE FROM {tabla}"),
                                  ("TRUNCATE", f"TRUNCATE {tabla}"), ("CREATE", f"CREATE TABLE {A.esquema}.x (a int)"),
                                  ("INSERT falso", f"INSERT INTO {tabla} (seq, sello, clase, cuerpo, hash_previo, hash)"
                                   f" VALUES (100000, now(), 'acceso', '{{}}', '{'0' * 64}', '{'0' * 64}')")):
            try:
                with conexion.transaction():
                    conexion.execute(sentencia)
                obtenidos[nombre] = PASA
            except psycopg.Error as error:
                obtenidos[nombre] = f"falla {error.sqlstate}"
        crear = conexion.execute("SELECT has_schema_privilege(%s, 'CREATE')", [A.esquema]).fetchone()[0]
        conexion.rollback()
    antes = conteo_tablas(A)
    # Un TRUNCATE simple de evento lo frena primero la clave foránea desde punto (0A000); con CASCADE
    # llega al disparador. En todos los casos la tabla queda igual.
    dueno = con_dueno([f"UPDATE {tabla} SET clase = clase", f"DELETE FROM {tabla}", f"TRUNCATE {tabla}",
                       f"TRUNCATE {tabla} CASCADE", f"TRUNCATE {A.esquema}.punto"])
    despues = conteo_tablas(A)
    ok = ([obtenidos[k] for k in ("UPDATE", "DELETE", "TRUNCATE", "CREATE")] == ["falla 42501"] * 4
          and obtenidos["INSERT falso"] == "falla 23000" and not crear
          and dueno[:2] == ["falla 23000"] * 2 and dueno[2] in ("falla 0A000", "falla 23000")
          and dueno[3:] == ["falla 23000"] * 2 and antes == despues and antes[0] > 0 and antes[1] > 0)
    return ok, (f"bit_rw: {', '.join(f'{k} {v}' for k, v in obtenidos.items())}, CREATE en esquema={crear};"
                f" propietario: UPDATE {dueno[0]}, DELETE {dueno[1]}, TRUNCATE {dueno[2]}, TRUNCATE CASCADE {dueno[3]},"
                f" TRUNCATE punto {dueno[4]}; filas (evento, punto) antes {antes}, después {despues}")


def b06():
    documentos = A.cliente.puntos()
    seqs = [d["payload"]["seq"] for d in documentos]
    multiplos = [s for s in seqs if s % CADA == 0]
    huella = claves.huella_publica(A.llave)
    firmas = all(puntos.firma_valida(d, huella) for d in documentos)
    nuevo = pedir(A.url + "/puntos", "POST")
    repetido = pedir(A.url + "/puntos", "POST")
    seq_nuevo = json.loads(nuevo[1])["payload"]["seq"]
    archivo = A.worm / almacen.nombre_de(seq_nuevo)
    contenido = archivo.read_bytes()
    try:
        almacen.AlmacenLocal(A.worm).guardar(seq_nuevo, b"otro contenido")
        local = "sobrescribió"
    except almacen.YaExiste:
        local = "rechaza"
    ok = (multiplos == [25, 50, 75, 100] and firmas and nuevo[0] == 201 and repetido[0] == 200
          and json.loads(repetido[1]) == json.loads(nuevo[1]) and archivo.read_bytes() == contenido and local == "rechaza")
    return ok, (f"puntos cada {CADA}: {multiplos}; firmas válidas={firmas}; bajo demanda {nuevo[0]}, repetido {repetido[0]}"
                f" sin sobrescribir; almacén local {local}")


class _AlmacenCaido:
    def guardar(self, seq, contenido):
        raise almacen.AlmacenNoDisponible("simulado")

    def leer(self, seq):
        raise almacen.AlmacenNoDisponible("simulado")

    def listar(self):
        raise almacen.AlmacenNoDisponible("simulado")


def b07():
    servicio = A.app.servicio
    original = servicio.c.almacen
    ultimo = A.cliente.consultar(orden="desc", limite=1)[0]["seq"]
    faltan = CADA - ultimo % CADA
    servicio.c.almacen = _AlmacenCaido()
    try:
        aceptados = [A.cliente.registrar(evento(operacion="O2.Ci"))["seq"] for _ in range(faltan)]
        degradado = json.loads(pedir(A.url + "/salud")[1])["estado"]
    finally:
        servicio.c.almacen = original
    A.cliente.registrar(evento(operacion="O2.Ci"))
    recuperado = json.loads(pedir(A.url + "/salud")[1])["estado"]
    creado = (A.worm / almacen.nombre_de(aceptados[-1])).exists()
    ok = len(aceptados) == faltan and degradado == "degradado" and recuperado == "ok" and creado
    return ok, f"{faltan} eventos aceptados con el almacén caído; salud {degradado}; tras reintentar {recuperado}, punto creado={creado}"


def b08():
    carpeta = Path(tempfile.mkdtemp(prefix="bitacora_verificar_"))
    try:
        huella = claves.huella_publica(A.llave)
        archivo = exportar(A, carpeta)
        lineas = archivo.read_bytes().splitlines()
        codigos = {"íntegra": verificar_script(archivo, A.worm, huella)}

        alterado = json.loads(lineas[5])
        alterado["resultado"] = "denegado"
        (carpeta / "alterado.jsonl").write_bytes(b"\n".join(lineas[:5] + [contrato.canonico(alterado)] + lineas[6:]) + b"\n")
        codigos["evento alterado"] = verificar_script(carpeta / "alterado.jsonl", A.worm, huella)

        reescritos, previo = [json.loads(l) for l in lineas], contrato.CEROS
        reescritos[5]["resultado"] = "denegado"
        for e in reescritos:
            e["hash_previo"] = previo
            e["hash"] = previo = contrato.hash_de_evento(e)
        (carpeta / "reescrito.jsonl").write_bytes(b"".join(contrato.canonico(e) + b"\n" for e in reescritos))
        codigos["cadena reescrita"] = verificar_script(carpeta / "reescrito.jsonl", A.worm, huella)

        otra = carpeta / "otra_llave"
        shutil.copytree(A.worm, otra)
        ajena = Ed25519PrivateKey.generate()
        evento_25 = json.loads(lineas[24])
        (otra / almacen.nombre_de(25)).write_bytes(contrato.canonico(puntos.documento(ajena, 25, evento_25["hash"], "2099-01-01T00:00:00.000000Z")))
        codigos["punto de otra llave"] = verificar_script(archivo, otra, huella)

        (carpeta / "malformado.jsonl").write_bytes(b"{no es json\n")
        codigos["malformado"] = verificar_script(carpeta / "malformado.jsonl", A.worm, huella)

        incompleta = carpeta / "incompleta"
        shutil.copytree(A.worm, incompleta)
        (incompleta / almacen.nombre_de(50)).unlink()
        codigos["punto faltante"] = verificar_script(archivo, incompleta, huella)
    finally:
        shutil.rmtree(carpeta, ignore_errors=True)
    esperados = {"íntegra": 0, "evento alterado": 1, "cadena reescrita": 3, "punto de otra llave": 2,
                 "malformado": 4, "punto faltante": 5}
    return codigos == esperados, ", ".join(f"{k} {v}" for k, v in codigos.items())


def b09():
    for _ in range(CADA + 3):
        B.cliente.registrar(evento(operacion="O1.Rg", servicio="carga"))
    integra_servicio = B.cliente.verificar()["codigo"]
    # Alteración simulada en un esquema temporal separado, confirmada: el servicio la lee con otra sesión.
    tabla = f"{B.esquema}.evento"
    alteracion = con_dueno([
        f"ALTER TABLE {tabla} DISABLE TRIGGER evento_inmutable",
        f"UPDATE {tabla} SET cuerpo = replace(cuerpo, '\"O1.Rg\"', '\"O1.Pr\"') WHERE seq = 3",
        f"ALTER TABLE {tabla} ENABLE TRIGGER evento_inmutable",
    ], confirmar=True)
    servicio = B.cliente.verificar()["codigo"]
    carpeta = Path(tempfile.mkdtemp(prefix="bitacora_verificar_"))
    try:
        script = verificar_script(exportar(B, carpeta), B.worm, claves.huella_publica(B.llave))
        script_a = verificar_script(exportar(A, carpeta), A.worm, claves.huella_publica(A.llave))
    finally:
        shutil.rmtree(carpeta, ignore_errors=True)
    servicio_a = A.cliente.verificar()["codigo"]
    ok = (integra_servicio == 0 and alteracion == [PASA] * 3 and servicio == script == 1
          and servicio_a == script_a == 0)
    return ok, f"íntegra: servicio {servicio_a}, script {script_a}; alterada: servicio {servicio}, script {script}"


def b10():
    u, v = str(uuid.uuid4()), str(uuid.uuid4())
    for identificador in (u, u, v):
        A.cliente.registrar(evento(usuario_id=identificador, operacion="O6.AR", objeto_tipo="cuenta", objeto_id=identificador))
    de_u = A.cliente.consultar(usuario_id=u, limite=500)
    de_v = A.cliente.consultar(usuario_id=v, limite=500)
    mismo = len(de_u) == 2 and de_u[0]["usuario"] == de_u[1]["usuario"]
    distintos = de_u[0]["usuario"] != de_v[0]["usuario"]
    otra_sal = contrato.seudonimo(os.urandom(32), u) != de_u[0]["usuario"]
    objeto = de_u[0]["objeto_id"] == de_u[0]["usuario"] != u
    with psycopg.connect(URL_RW, connect_timeout=15) as conexion:
        en_base = conexion.execute(
            f"SELECT count(*) FROM {A.esquema}.evento WHERE strpos(cuerpo, %s) > 0 OR strpos(coalesce(objeto_id, ''), %s) > 0",
            [u, u]).fetchone()[0]
    en_registro = any(u in linea for linea in REGISTRO.lineas)
    ok = mismo and distintos and otra_sal and objeto and en_base == 0 and not en_registro
    return ok, (f"mismo usuario mismo seudónimo={mismo}; distintos={distintos}; otra sal otro={otra_sal};"
                f" cuenta como objeto seudonimizada={objeto}; identificador en la base {en_base}, en el registro {en_registro}")


# --------------------------------------------------------------------------- de punta a punta con el PEP


def nuevo_pep() -> pep.PEP:
    return pep.PEP(bitacora=A.cliente, pdp=pdp.MotorPython())


def acciones_de(usuario, **filtros) -> list[dict]:
    return A.cliente.consultar(usuario_id=str(usuario.pk), limite=500, **filtros)


def e01():
    p, d = nuevo_pep(), pa.Datos()
    r7 = d.usuario("R7")
    salida = p.ejecutar("O2.Ab", pa.S(r7), inicio=ps.INICIO, fin=ps.FIN)
    eventos = acciones_de(r7)
    intento = next((e for e in eventos if e["accion"] == "intento"), {})
    resultado = next((e for e in eventos if e["accion"] == "resultado"), {})
    campos = all(e.get("operacion") == "O2.Ab" and e.get("rol_activo") == "R7" and len(e.get("version_politica", "")) == 64
                 and e.get("servicio") == "abrir_periodo" for e in (intento, resultado))
    ok = salida.permitido and intento.get("decision") == "concedido" and resultado.get("resultado") == "exito" and campos
    return ok, f"intento y resultado con operación, rol, servicio y versión de política={campos}"


def e02():
    p, d = nuevo_pep(), pa.Datos()
    r7 = d.usuario("R7")
    p.decidir("O1.MdC", pa.S(r7))
    denegacion = next((e for e in acciones_de(r7) if e["accion"] == "denegacion"), {})
    ok = denegacion.get("regla") == "defecto" and denegacion.get("decision") == "denegado" and denegacion.get("clase") == "acceso"
    return ok, f"denegación con regla {denegacion.get('regla')} y clase {denegacion.get('clase')}"


def e03():
    p, d = nuevo_pep(), pa.Datos()
    ctx = d.base()
    salida = p.decidir("O1.L", pa.S(ctx["r7"]), Objeto("medicion", ctx["medicion"]))
    lectura = next((e for e in acciones_de(ctx["r7"]) if e["accion"] == "lectura"), {})
    ok = (salida.permitido and lectura.get("objeto_id") == str(ctx["medicion"]) and lectura.get("finca_id") == str(ctx["finca"])
          and lectura.get("periodo_id") == str(ctx["periodo"]) and lectura.get("clase") == "consulta")
    return ok, f"lectura de R7 registrada con objeto, finca y período={ok}"


def e04():
    p, d = nuevo_pep(), pa.Datos()
    ctx = pa.certificado_de_finca(d)
    dueno = ctx["propietarios"][0]
    salida = p.ejecutar("O3.Ex", pa.S(dueno), Objeto("certificado", ctx["certificado"]), certificado_id=ctx["certificado"])
    exportacion = next((e for e in acciones_de(dueno) if e["accion"] == "exportacion"), {})
    ok = salida.permitido and exportacion.get("huella_exportacion") == salida.resultado.huella_sha256
    return ok, f"exportación con la huella SHA-256 de lo exportado={ok}"


def e05():
    p, d = nuevo_pep(), pa.Datos()
    ctx = d.cerrada()
    lectura = d.base(ctx={**d.finca(), "indice": 6})
    A.detener()
    try:
        disponible = A.cliente.disponible()
        aprobar = p.ejecutar("O1.Ap", pa.S(ctx["r2"]), Objeto("medicion", ctx["medicion"]), medicion_id=ctx["medicion"],
                             huella_revisada=ctx["huella"])
        leer = p.decidir("O1.L", pa.S(lectura["r7"]), Objeto("medicion", lectura["medicion"]))
        enmendar = p.ejecutar("O4.So", pa.S(ctx["tecnico"]), Objeto("medicion", ctx["medicion"]), medicion_id=ctx["medicion"],
                              motivo=ps.MOTIVO, co2e_nuevo=ps.CO2E_CORREGIDO, fecha_nueva=ps.FECHA_CORREGIDA)
    finally:
        A.reiniciar()
    de_nuevo = p.decidir("O1.L", pa.S(lectura["r7"]), Objeto("medicion", lectura["medicion"]))
    caidas = [pa.clasificar(s) for s in (aprobar, leer, enmendar)]
    ok = not disponible and caidas == [("D", "Cd8"), ("D", "Cd17"), ("D", "Cd11")] and de_nuevo.permitido
    return ok, f"servicio detenido: aprobar {caidas[0][1]}, leer R7 {caidas[1][1]}, enmendar {caidas[2][1]}; de nuevo disponible: {pa.clasificar(de_nuevo)[0]}"


def e06():
    p, d = nuevo_pep(), pa.Datos()
    for operacion in ("O6.AR", "O5.Cr", "O1.Ap"):
        A.cliente.registrar(evento(accion="resultado", operacion=operacion, resultado="exito"))
    A.cliente.registrar(evento(accion="lectura", operacion="O1.L"))
    r7 = d.usuario("R7")
    vistos = cliente_bitacora.consultar(p, pa.S(r7), limite=500)
    clases = {e["clase"] for e in vistos}
    administracion = {e.get("operacion", "")[:2] for e in vistos if e["clase"] == "administracion"}
    ctx = d.base()
    auditor = pa.auditor_con_ventana(d, ctx)
    del_auditor = cliente_bitacora.consultar(p, pa.S(auditor), limite=500)
    sin_ventana = cliente_bitacora.consultar(p, pa.S(pa.auditor_con_ventana(d, ctx, vigente=False)), limite=500)
    ok = (isinstance(vistos, list) and clases <= {"certificacion", "administracion"} and "certificacion" in clases
          and administracion <= {"O6", "O8"} and isinstance(del_auditor, list)
          and {"consulta", "acceso"} <= {e["clase"] for e in del_auditor}
          and pa.clasificar(sin_ventana) == ("D", "Cd3"))
    return ok, (f"R7 ve clases {sorted(clases)} y administración {sorted(administracion)}; auditor en ventana ve"
                f" consulta y acceso; fuera de ventana {pa.clasificar(sin_ventana)[1]}")


def e10():
    """R7 no ve autenticación ni denegaciones aunque existan en la bitácora."""
    p, d = nuevo_pep(), pa.Datos()
    accesos = A.cliente.consultar(clases=["acceso"], limite=500)
    acciones_existentes = {e["accion"] for e in accesos}
    vistos = cliente_bitacora.consultar(p, pa.S(d.usuario("R7")), limite=500)
    ocultas = {"inicio_sesion", "segundo_factor", "bloqueo", "denegacion"}
    vistas = {e["accion"] for e in vistos} & ocultas
    ok = {"inicio_sesion", "denegacion"} <= acciones_existentes and isinstance(vistos, list) and not vistas
    return ok, (f"en la bitácora hay {sorted(acciones_existentes & ocultas)}; R7 ve de ellas {sorted(vistas)}"
                f" ({len(vistos)} eventos visibles)")


def e07():
    antes = Alerta.objects.filter(tipo="bitacora_integridad").count()
    call_command("verificar_bitacora", url=A.url, stdout=open(os.devnull, "w"))
    sin_fallo = Alerta.objects.filter(tipo="bitacora_integridad").count() - antes
    try:
        call_command("verificar_bitacora", url=B.url, stdout=open(os.devnull, "w"))
        fallo = "sin error"
    except CommandError:
        fallo = "CommandError"
    alertas = list(Alerta.objects.filter(tipo="bitacora_integridad").order_by("-creada_en")[:1])
    ok = sin_fallo == 0 and fallo == "CommandError" and alertas and alertas[0].prioridad == "prioritaria"
    return ok, f"íntegra: alertas nuevas {sin_fallo}; alterada: {fallo}, alerta {alertas[0].prioridad if alertas else '-'}"


def e08():
    salida = open(os.devnull, "w")
    call_command("registrar_version_politica", url=A.url, stdout=salida)
    call_command("registrar_version_politica", url=A.url, stdout=salida)
    versiones = A.cliente.consultar(objeto_tipo="politica", limite=500)
    return len(versiones) == 1, f"eventos de versión de política tras dos ejecuciones: {len(versiones)}"


def e09():
    d = pa.Datos()
    usuario = d.usuario("R1")
    cliente_bitacora.cliente_configurado.cache_clear()
    try:
        with override_settings(BITACORA_URL=A.url):
            autenticacion.registrar_evento("acceso_fallido", "contrasena_invalida", usuario.pk)
        cliente_bitacora.cliente_configurado.cache_clear()
        with override_settings(BITACORA_URL=f"http://127.0.0.1:{pa.puerto_libre()}"):
            autenticacion.registrar_evento("acceso_fallido", "contrasena_invalida", usuario.pk)
            sin_excepcion = True
    finally:
        cliente_bitacora.cliente_configurado.cache_clear()
    fallos = [e for e in acciones_de(usuario) if e["accion"] == "inicio_sesion"]
    ok = len(fallos) == 1 and fallos[0].get("motivo") == "contrasena_invalida" and fallos[0].get("resultado") == "fallo" and sin_excepcion
    return ok, f"evento de autenticación registrado={len(fallos) == 1}; con la bitácora caída no bloquea={sin_excepcion}"


PRUEBAS = [
    ("B01", "Anexar y reproducir el hash con la fórmula documentada", "reproducido, contiguo, monótono", b01),
    ("B02", "Cuerpo con hash, seq, sello y clase falsos", "se ignoran", b02),
    ("B03", "Campos desconocidos, tipos, tamaño, rutas y métodos", "400, 400, 413, 400, 404, 405, 405", b03),
    ("B04", "Concurrencia real: 4 hilos por 25 eventos", "sin huecos ni duplicados; cadena válida", b04),
    ("B05", "bit_rw sin UPDATE, DELETE, TRUNCATE ni CREATE; propietario rechazado", "42501 x4; 23000, 23000, 0A000 o 23000, 23000, 23000; filas intactas", b05),
    ("B06", "Puntos cada N y bajo demanda; firma; no se sobrescriben", "25, 50, 75, 100; 201 y 200", b06),
    ("B07", "Almacén WORM caído: el evento se conserva y se reintenta", "degradado y luego ok", b07),
    ("B08", "verify_bitacora.py: íntegra, alterada, reescrita, otra llave, malformada, faltante", "0, 1, 3, 2, 4, 5", b08),
    ("B09", "POST /verificar coincide con el script", "0 y 0; 1 y 1", b09),
    ("B10", "Seudonimización", "estable, distinta, sin identificador", b10),
    ("E01", "PEP: operación concedida deja intento y resultado", "con sus campos", e01),
    ("E02", "PEP: denegación con su regla", "regla defecto", e02),
    ("E03", "PEP: lectura de R7 registrada", "objeto, finca y período", e03),
    ("E04", "PEP: exportación con la huella de lo exportado", "huella coincide", e04),
    ("E05", "Servicio detenido: aprobar, leer como R7 y enmendar fallan cerrado (casos 20 y 41)", "Cd8, Cd17, Cd11; luego C", e05),
    ("E06", "Consulta de R7 limitada; auditor dentro y fuera de ventana", "clases de R7; consulta; Cd3", e06),
    ("E07", "manage.py verificar_bitacora", "sin alerta; alerta prioritaria", e07),
    ("E08", "manage.py registrar_version_politica no repite la versión", "1", e08),
    ("E09", "Eventos de autenticación con mejor esfuerzo", "registrado; caída no bloquea", e09),
    ("E10", "R7 no ve inicios de sesión ni denegaciones", "ninguno visible", e10),
]


def esquemas_restantes(nombres: list[str]) -> int:
    with psycopg.connect(URL_DUENO, connect_timeout=15) as conexion:
        return conexion.execute("SELECT count(*) FROM pg_namespace WHERE nspname = ANY(%s)", [nombres]).fetchone()[0]


def main() -> int:
    global A, B
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    registro = logging.getLogger("bitacora_svc")
    registro.addHandler(REGISTRO)
    registro.setLevel(logging.INFO)
    registro.propagate = False
    logging.getLogger("verdeazul").setLevel(logging.ERROR)
    nombres = [f"{esquema.PREFIJO_PRUEBA}{uuid.uuid4().hex[:10]}" for _ in range(2)]
    try:
        A, B = Instancia(nombres[0]), Instancia(nombres[1])
        ps.usar(ps.APP)
        iniciales = pa.conteos()
        resultados = [ps.ejecutar(*prueba) for prueba in PRUEBAS]
        finales = pa.conteos()
        totales = {"eventos A": A.app.servicio.salud()["ultimo_seq"], "eventos B": B.app.servicio.salud()["ultimo_seq"],
                   "puntos A": len(A.cliente.puntos())}
    finally:
        for instancia in (A, B):
            if instancia is not None:
                instancia.cerrar()
        ps.connections["default"].close()
    restantes = esquemas_restantes(nombres)
    pm.imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    print(f"\nTotal: {correctas}/{len(resultados)} OK")
    print(f"Bitácora de prueba: {totales}; tiempos: {LATENCIA}")
    print(f"Esquemas temporales restantes: {restantes}")
    limpio = finales == iniciales
    print(f"Conteos del negocio antes: {iniciales}")
    print(f"Conteos del negocio después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio and restantes == 0 else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio and restantes == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
