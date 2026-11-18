#!/usr/bin/env python3
"""Pruebas de punta a punta de la capa de autorización (PEP, PIP, PDP y servicios) contra la base dev.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_autorizacion.py

Arranca un OPA local con el binario indicado en .opa_local.json (fuera del repositorio), usa los dos
backends del PDP y compara sus decisiones en cada llamada (paridad). Corre como app_rw con el
patrón de probar_cuentas.py: cada prueba en una transacción que se revierte y conteos comparados al
final; el registro de accesos (con FORCE RLS) se cuenta como migrador dentro de una transacción
revertida. Imprime solo resultados, totales y conteos.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import probar_cuentas as pk  # noqa: E402  (configura Django y la conexión de app_rw)

import psycopg  # noqa: E402

import probar_catalogo as pc  # noqa: E402
import probar_mediciones as pm  # noqa: E402
import probar_servicios as ps  # noqa: E402
from autorizacion import motor, pdp, pep, pip  # noqa: E402
from autorizacion.bitacora import BitacoraEnMemoria  # noqa: E402
from autorizacion.pip import Objeto  # noqa: E402
from catalogo import servicios as catalogo  # noqa: E402
from mediciones import servicios  # noqa: E402
from mediciones.models import Alerta, Certificado, Medicion, Periodo  # noqa: E402
from mediciones.transaccion import hora_de_la_base  # noqa: E402
from usuarios import servicios as cuentas  # noqa: E402
from usuarios.models import AccesoEmergencia  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
PASA = ps.PASA
DENEGADAS_A_TODOS = {"O1.MdC", "O1.El", "O2.Ro", "O3.El", "O4.El", "O5.El", "O7.Es", "O7.MdE", "O8.Cf"}
# Región de parcelas de historial (contadores de H2), distinta de la de los demás scripts.
X_HISTORIAL, Y_HISTORIAL = 1200000, 1100000
LABORAL = (2, 10)
SABADO = (6, 10)
JUSTIFICACION = "Revisión de la anulación con la gerencia de la empresa"
TABLA_ACCESOS = "autorizacion_registroacceso"

TODOS = {
    "asignacion_vigente": True,
    "propietario": True,
    "ventana_vigente": True,
    "segundo_factor": True,
    "proyeccion_disponible": True,
    "bitacora_disponible": True,
    "estado_visible_r2": True,
    "misma_region": True,
    "h2": {"disponible": True, "ajena": False, "wc": 0, "wl": 0, "laboral": True},
}
PARAMETROS = {
    "h2_wc_laboral_blando": 10, "h2_wc_laboral_duro": 25, "h2_wc_fuera_blando": 3,
    "h2_wc_fuera_duro": 8, "h2_wl_blando": 40, "h2_wl_duro": 100,
}


# --------------------------------------------------------------------------- OPA local y paridad


def puerto_libre() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def iniciar_opa() -> tuple[subprocess.Popen, str]:
    configuracion = RAIZ / ".opa_local.json"
    if not configuracion.exists():
        raise SystemExit("[FALLO] Falta .opa_local.json con la ruta del binario de OPA (ver CONTRIBUTING.md).")
    binario = json.loads(configuracion.read_text(encoding="utf-8"))["opa"]
    puerto = puerto_libre()
    proceso = subprocess.Popen(
        [binario, "run", "--server", f"--addr=127.0.0.1:{puerto}", "--log-level=error",
         str(RAIZ / "policy" / "autorizacion.rego"),
         f"verdeazul.matriz:{RAIZ / 'autorizacion' / 'matriz.json'}",
         f"verdeazul.politica:{RAIZ / 'autorizacion' / 'politica.json'}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{puerto}"
    for _ in range(100):
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=1) as r:
                if r.status == 200:
                    return proceso, url
        except Exception:
            time.sleep(0.1)
    proceso.terminate()
    raise SystemExit("[FALLO] OPA local no arrancó.")


class Comparador:
    """PDP que consulta OPA y el motor de Python, devuelve la de OPA y anota las diferencias."""

    def __init__(self, opa, python):
        self.opa, self.python = opa, python
        self.comparadas = 0
        self.diferencias: list[str] = []

    def decidir(self, entrada: dict) -> dict:
        de_opa = self.opa.decidir(entrada)
        de_python = self.python.decidir(entrada)
        self.comparadas += 1
        if de_opa != de_python:
            self.diferencias.append(entrada["operacion"])
        return de_opa


# --------------------------------------------------------------------------- contexto de pruebas


class Entorno:
    def __init__(self, comparador):
        self.comparador = comparador
        self.bitacora = BitacoraEnMemoria()
        self.cierres: list = []
        self.pep = pep.PEP(bitacora=self.bitacora, pdp=comparador, cerrar_sesion=self.cierres.append)

    def reiniciar(self):
        self.bitacora.esta_disponible = True
        self.bitacora.fallar_registro = False
        self.bitacora.eventos.clear()
        self.cierres.clear()


ENTORNO: Entorno | None = None


def P() -> pep.PEP:
    return ENTORNO.pep


def S(usuario, mfa: bool = True, edad: int = 30) -> pep.Sesion:
    if mfa:
        return pep.Sesion(usuario, pep.NIVEL_SEGUNDO_FACTOR, time.time() - edad)
    return pep.Sesion(usuario, pep.NIVEL_CONTRASENA, None)


class Datos(pk.Datos):
    def base(self, co2e=ps.CO2E_BAJO, ctx=None) -> dict:
        """Finca con propietario R6, parcela con técnico asignado, período abierto y medición en borrador."""
        ctx = ctx or self.finca()
        ctx["parcela"] = self.parcela(ctx, ctx.get("indice", 0))
        ctx.update(tecnico=self.usuario("R1"), r2=self.usuario("R2"), r2b=self.usuario("R2"), r4=self.usuario("R4"))
        catalogo.asignar_tecnico(ctx["r3"], ctx["parcela"], ctx["tecnico"].pk, hora_de_la_base() + timedelta(days=30))
        ctx["periodo"] = servicios.abrir_periodo(ctx["r7"], ps.INICIO, ps.FIN).periodo_id
        registro = servicios.registrar_medicion(
            ctx["tecnico"], ctx["parcela"], ctx["periodo"], co2e_toneladas=co2e, fecha_muestreo=ps.FECHA
        )
        ctx["medicion"], ctx["huella"] = registro.medicion_id, registro.huella
        return ctx

    def presentada(self, co2e=ps.CO2E_BAJO, ctx=None) -> dict:
        ctx = self.base(co2e, ctx)
        servicios.presentar_medicion(ctx["tecnico"], ctx["medicion"])
        return ctx

    def cerrada(self, co2e=ps.CO2E_BAJO, ctx=None) -> dict:
        ctx = self.presentada(co2e, ctx)
        servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
        return ctx

    def certificada(self, co2e=ps.CO2E_BAJO, ctx=None) -> dict:
        ctx = self.cerrada(co2e, ctx)
        ctx["certificado"] = servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]).certificado_id
        return ctx

    def cambiar_rol(self, ctx, usuario, anterior: str, nuevo: str):
        cuentas.revocar_rol(ctx["r4"], usuario.pk, anterior)
        cuentas.asignar_rol(ctx["r4"], usuario.pk, nuevo)

    def historial(self, sujeto, n: int) -> None:
        """n parcelas ajenas distintas ya consultadas (concedidas) por el sujeto."""
        if n <= 0:
            return
        finca = uuid.uuid4()
        self.sql("INSERT INTO catalogo_finca (id, nombre, creada_en) VALUES (%s, 'Finca de historial', now())", [finca])
        self.sql(
            "INSERT INTO catalogo_parcela (id, finca_id, codigo, geom)"
            " SELECT gen_random_uuid(), %s, 'H-' || g, ST_MakeEnvelope(%s + g * 200, %s, %s + g * 200 + 100, %s + 100, 5367)"
            "   FROM generate_series(1, %s) AS g",
            [finca, X_HISTORIAL, Y_HISTORIAL, X_HISTORIAL, Y_HISTORIAL, n],
        )
        self.actor(sujeto)
        self.sql(
            f"INSERT INTO {TABLA_ACCESOS} (id, usuario_id, parcela_id, operacion, ajena, resultado)"
            " SELECT gen_random_uuid(), %s, p.id, 'O1.L', true, 'concedido' FROM catalogo_parcela p WHERE p.finca_id = %s",
            [sujeto.pk, finca],
        )

    def lectura_ajena(self, rol: str = "R1", historial: int = 0, presentar: bool = False) -> dict:
        """Sujeto R1 (asignado a una parcela de la finca) o R2 y una medición de otra parcela de la misma finca."""
        ctx = self.finca()
        ctx["propia"] = self.parcela(ctx, 0)
        ctx["sujeto"] = self.usuario(rol)
        if rol == "R1":
            catalogo.asignar_tecnico(ctx["r3"], ctx["propia"], ctx["sujeto"].pk, hora_de_la_base() + timedelta(days=30))
        ctx["indice"] = 1
        self.base(ctx=ctx)
        if presentar:
            servicios.presentar_medicion(ctx["tecnico"], ctx["medicion"])
        self.historial(ctx["sujeto"], historial)
        return ctx


def clasificar(salida) -> tuple[str, str]:
    if isinstance(salida, pep.Denegado):
        return "D", salida.condicion
    restricciones = set(salida.decision["restricciones"])
    if {motor.RESTRICCION_2FA, motor.RESTRICCION_AVISO} <= restricciones:
        return "CR", "Cd9"
    return "C", ""


def aviso_h2(usuario) -> bool:
    return Alerta.objects.filter(tipo=pep.TIPO_H2_UMBRAL_BLANDO, usuario_id=usuario.pk).exists()


# --------------------------------------------------------------------------- casos de la matriz


def leer_ajena(rol, historial, momento, presentar=False):
    d = Datos()
    ctx = d.lectura_ajena(rol, historial, presentar)
    with mock.patch.object(pip, "_momento_local", return_value=momento):
        salida = P().decidir("O1.L", S(ctx["sujeto"]), Objeto("medicion", ctx["medicion"]))
    return salida, ctx


def k01():
    d = Datos()
    ctx = d.finca()
    ctx["parcela"] = d.parcela(ctx)
    tecnico = d.usuario("R1")
    catalogo.asignar_tecnico(ctx["r3"], ctx["parcela"], tecnico.pk, hora_de_la_base() + timedelta(days=30))
    periodo = servicios.abrir_periodo(ctx["r7"], ps.INICIO, ps.FIN).periodo_id
    return P().ejecutar("O1.Rg", S(tecnico), Objeto("parcela", ctx["parcela"]), parcela_id=ctx["parcela"],
                        periodo_id=periodo, co2e_toneladas=ps.CO2E_BAJO, fecha_muestreo=ps.FECHA)


def k02():
    d = Datos()
    ctx = d.finca()
    ctx["parcela"] = d.parcela(ctx)
    periodo = servicios.abrir_periodo(ctx["r7"], ps.INICIO, ps.FIN).periodo_id
    return P().ejecutar("O1.Rg", S(d.usuario("R1")), Objeto("parcela", ctx["parcela"]), parcela_id=ctx["parcela"],
                        periodo_id=periodo, co2e_toneladas=ps.CO2E_BAJO, fecha_muestreo=ps.FECHA)


def k03():
    d = Datos()
    ctx = d.base()
    servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    otra = d.parcela(ctx, 1)
    catalogo.asignar_tecnico(ctx["r3"], otra, ctx["tecnico"].pk, hora_de_la_base() + timedelta(days=30))
    return P().ejecutar("O1.Rg", S(ctx["tecnico"]), Objeto("parcela", otra), parcela_id=otra,
                        periodo_id=ctx["periodo"], co2e_toneladas=ps.CO2E_BAJO, fecha_muestreo=ps.FECHA)


def k04():
    d = Datos()
    ctx = d.base()
    return P().ejecutar("O1.Md", S(ctx["tecnico"]), Objeto("medicion", ctx["medicion"]), medicion_id=ctx["medicion"],
                        co2e_toneladas=ps.CO2E_CORREGIDO, fecha_muestreo=ps.FECHA)


def k05():
    d = Datos()
    ctx = d.presentada()
    return P().ejecutar("O1.Md", S(ctx["tecnico"]), Objeto("medicion", ctx["medicion"]), medicion_id=ctx["medicion"],
                        co2e_toneladas=ps.CO2E_CORREGIDO, fecha_muestreo=ps.FECHA)


def k06():
    d = Datos()
    salidas = [P().decidir("O1.MdC", S(d.usuario(rol))) for rol in motor.matriz()["roles"]]
    todas = all(isinstance(s, pep.Denegado) and s.condicion == "defecto" for s in salidas)
    return (salidas[0], todas, f"7 roles defecto={todas}")


def k07():
    salida, _ = leer_ajena("R1", 3, LABORAL)
    return salida


def k08():
    d = Datos()
    ctx = d.finca()
    tecnico = d.usuario("R1")
    catalogo.asignar_tecnico(ctx["r3"], d.parcela(ctx, 0), tecnico.pk, hora_de_la_base() + timedelta(days=30))
    otra = d.base(ctx={**d.finca(), "indice": 5})
    with mock.patch.object(pip, "_momento_local", return_value=LABORAL):
        return P().decidir("O1.L", S(tecnico), Objeto("medicion", otra["medicion"]))


def k09():
    salida, ctx = leer_ajena("R1", 11, LABORAL)
    return salida, aviso_h2(ctx["sujeto"]), f"aviso a R7={aviso_h2(ctx['sujeto'])}"


def k10():
    salida, ctx = leer_ajena("R1", 24, LABORAL)
    return salida, len(ENTORNO.cierres) == 1, f"cierre de sesión={len(ENTORNO.cierres)}"


def k11():
    salida, ctx = leer_ajena("R1", 4, SABADO)
    return salida, aviso_h2(ctx["sujeto"]), f"aviso a R7={aviso_h2(ctx['sujeto'])}"


def k12():
    salida, _ = leer_ajena("R1", 7, SABADO)
    return salida


def k13():
    salida, _ = leer_ajena("R1", 100, LABORAL)
    return salida


def aprobar(ctx, usuario, huella=None, sesion=None):
    return P().ejecutar("O1.Ap", sesion or S(usuario), Objeto("medicion", ctx["medicion"]),
                        medicion_id=ctx["medicion"], huella_revisada=huella or ctx["huella"])


def k14():
    ctx = Datos().cerrada()
    return aprobar(ctx, ctx["r2"])


def k15():
    d = Datos()
    ctx = d.cerrada()
    d.cambiar_rol(ctx, ctx["tecnico"], "R1", "R2")
    return aprobar(ctx, ctx["tecnico"])


def k16():
    ctx = Datos().cerrada()
    return aprobar(ctx, ctx["r2"], sesion=S(ctx["r2"], mfa=False))


def k17():
    ctx = Datos().presentada()
    return aprobar(ctx, ctx["r2"])


def k18():
    ctx = Datos().base()
    return aprobar(ctx, ctx["r2"])


def k19():
    ctx = Datos().cerrada()
    return aprobar(ctx, ctx["r2"], huella="e" * 64)


def k20():
    ctx = Datos().cerrada()
    ENTORNO.bitacora.esta_disponible = False
    return aprobar(ctx, ctx["r2"])


def k21():
    ctx = Datos().certificada()
    return aprobar(ctx, ctx["r2b"])


def k22():
    ctx = Datos().cerrada(ps.CO2E_ALTO)
    primera = aprobar(ctx, ctx["r2"])
    return aprobar(ctx, ctx["r2"]), primera.permitido, f"primera aprobación concedida={primera.permitido}"


def k23():
    ctx = Datos().cerrada(ps.CO2E_ALTO)
    aprobar(ctx, ctx["r2"])
    salida = aprobar(ctx, ctx["r2b"])
    certificada = Medicion.objects.filter(pk=ctx["medicion"]).values_list("estado", flat=True).first() == "certificada"
    return salida, certificada, f"certificada={certificada}"


def k24():
    ctx = Datos().cerrada()
    return P().ejecutar("O1.Dv", S(ctx["r2"]), Objeto("medicion", ctx["medicion"]), medicion_id=ctx["medicion"],
                        huella_revisada=ctx["huella"])


def solicitar(ctx, dias, solicitante=None):
    cerrado = Periodo.objects.filter(pk=ctx["periodo"]).values_list("cerrado_en", flat=True).get()
    with ps.con_ahora(cerrado + timedelta(days=dias)):
        return P().ejecutar("O4.So", S(solicitante or ctx["tecnico"]), Objeto("medicion", ctx["medicion"]),
                            medicion_id=ctx["medicion"], motivo=ps.MOTIVO, co2e_nuevo=ps.CO2E_CORREGIDO,
                            fecha_nueva=ps.FECHA_CORREGIDA, notas_nuevas=ps.NOTAS_CORREGIDAS)


def k25():
    return solicitar(Datos().cerrada(), 10)


def k26():
    return solicitar(Datos().cerrada(), 120)


def k27():
    ctx = Datos().certificada()
    servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=JUSTIFICACION)
    return solicitar(ctx, 120)


def resolver(ctx, autorizador, enmienda):
    return P().ejecutar("O4.Au", S(autorizador), Objeto("enmienda", enmienda), enmienda_id=enmienda, autorizar=True)


def k28():
    ctx = Datos().cerrada()
    enmienda = ps.solicitar(ctx).enmienda_id
    return resolver(ctx, ctx["r7b"], enmienda)


def k29():
    d = Datos()
    ctx = d.certificada()
    enmienda = ps.solicitar(ctx).enmienda_id
    d.cambiar_rol(ctx, ctx["r2"], "R2", "R7")
    return resolver(ctx, ctx["r2"], enmienda)


def k30():
    d = Datos()
    ps.como_dueno(d)
    ctx = d.presentada()
    ps.cierre_en_el_pasado(d, ctx, 120)
    primero = servicios.aprobar_medicion(ctx["r2"], ctx["medicion"], huella_revisada=ctx["huella"]).certificado_id
    servicios.anular_certificado(ctx["r7"], primero, justificacion=JUSTIFICACION)
    enmienda = ps.solicitar(ctx).enmienda_id
    servicios.aprobar_medicion(ctx["r2b"], ctx["medicion"], huella_revisada=ctx["huella"])
    return resolver(ctx, ctx["r7b"], enmienda)


def certificado_de_finca(d, *propietarios):
    ctx = d.finca(*propietarios)
    return d.certificada(ctx=ctx)


def k31():
    d = Datos()
    p1, p2 = d.usuario("R6"), d.usuario("R6")
    ctx = certificado_de_finca(d, p1, p2)
    salida = P().decidir("O3.L", S(p2), Objeto("certificado", ctx["certificado"]))
    proyeccion = getattr(salida, "decision", {}).get("proyeccion")
    return salida, proyeccion == "dueno", f"proyección {proyeccion}"


def k32():
    d = Datos()
    ctx = certificado_de_finca(d)
    return P().decidir("O3.L", S(d.usuario("R6")), Objeto("certificado", ctx["certificado"]))


def k33():
    d = Datos()
    ctx = d.base()
    return P().ejecutar("O1.Md", S(ctx["propietarios"][0]), Objeto("medicion", ctx["medicion"]),
                        medicion_id=ctx["medicion"], co2e_toneladas=ps.CO2E_CORREGIDO, fecha_muestreo=ps.FECHA)


def k34():
    d = Datos()
    ctx = certificado_de_finca(d)
    salida = P().ejecutar("O3.Ex", S(ctx["propietarios"][0]), Objeto("certificado", ctx["certificado"]),
                          certificado_id=ctx["certificado"])
    exportado = salida.permitido and len(salida.resultado.huella_sha256) == 64
    return salida, exportado, f"exportado={exportado}"


def auditor_con_ventana(d, ctx, vigente: bool = True):
    auditor = d.usuario("R5")
    if vigente:
        ahora = hora_de_la_base()
        ventana = cuentas.solicitar_ventana(ctx["r7"], auditor.pk, ahora - timedelta(hours=1), ahora + timedelta(days=1))
        cuentas.abrir_ventana(ctx["r4"], ventana.ventana_id)
    return auditor


def k35():
    d = Datos()
    ctx = d.presentada()
    return P().decidir("O1.L", S(auditor_con_ventana(d, ctx)), Objeto("medicion", ctx["medicion"]))


def k36():
    d = Datos()
    ctx = d.presentada()
    return P().decidir("O1.L", S(auditor_con_ventana(d, ctx, False)), Objeto("medicion", ctx["medicion"]))


def k37():
    d = Datos()
    ctx = d.certificada()
    auditor = auditor_con_ventana(d, ctx)
    return P().ejecutar("O3.Ex", S(auditor, mfa=False), Objeto("certificado", ctx["certificado"]),
                        certificado_id=ctx["certificado"])


def k38():
    d = Datos()
    ctx = d.base()
    auditor = auditor_con_ventana(d, ctx)
    return P().ejecutar("O1.Md", S(auditor), Objeto("medicion", ctx["medicion"]), medicion_id=ctx["medicion"],
                        co2e_toneladas=ps.CO2E_CORREGIDO, fecha_muestreo=ps.FECHA)


def k39():
    salida, ctx = leer_ajena("R2", 11, LABORAL, presentar=True)
    return salida, aviso_h2(ctx["sujeto"]), f"aviso a R7={aviso_h2(ctx['sujeto'])}"


def k40():
    d = Datos()
    ctx = d.base()
    salida = P().decidir("O1.L", S(ctx["r7"]), Objeto("medicion", ctx["medicion"]))
    registrada = any(e["tipo"] == "lectura" for e in ENTORNO.bitacora.eventos)
    return salida, registrada, f"lectura registrada={registrada}"


def k41():
    d = Datos()
    ctx = d.base()
    ENTORNO.bitacora.esta_disponible = False
    return P().decidir("O1.L", S(ctx["r7"]), Objeto("medicion", ctx["medicion"]))


def rol(actor, usuario, codigo, servicio="asignar_rol"):
    return P().ejecutar("O6.AR", S(actor), Objeto("cuenta", usuario.pk), servicio=servicio, usuario_id=usuario.pk, rol=codigo)


def k42():
    d = Datos()
    return rol(d.usuario("R4"), d.usuario("R1"), "R2")


def k43():
    d = Datos()
    return rol(d.usuario("R4"), d.usuario(), "R1")


def k44():
    d = Datos()
    r4 = d.usuario("R4")
    return rol(r4, r4, "R3")


def k70():
    d = Datos()
    return rol(d.usuario("R4"), d.usuario("R2"), "R3")


def k45():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    tecnico = d.usuario("R1")
    salida = P().ejecutar("O5.As", S(ctx["r3"]), Objeto("parcela", parcela), parcela_id=parcela,
                          tecnico_id=tecnico.pk, vence_en=hora_de_la_base() + timedelta(days=7))
    aviso = Alerta.objects.filter(tipo="asignacion_tecnico", cuenta_afectada_id=tecnico.pk).exists()
    return salida, aviso, f"aviso a R7={aviso}"


def k46():
    d = Datos()
    ctx = d.finca()
    parcela = d.parcela(ctx)
    tecnico = d.usuario("R1", "R3")
    return P().ejecutar("O5.As", S(tecnico), Objeto("parcela", parcela), parcela_id=parcela,
                        tecnico_id=tecnico.pk, vence_en=hora_de_la_base() + timedelta(days=7))


def k47():
    d = Datos()
    ctx = d.certificada()
    nuevo = d.usuario("R6")
    salida = P().ejecutar("O5.Md", S(ctx["r3"]), Objeto("finca", ctx["finca"]), servicio="cambiar_propietarios",
                          finca_id=ctx["finca"], agregar=[nuevo.pk], retirar=[ctx["propietarios"][0].pk])
    aviso = Alerta.objects.filter(tipo="cambio_propietarios", cuenta_afectada_id=nuevo.pk).exists()
    return salida, aviso, f"aviso a R7={aviso}"


def k48():
    d = Datos()
    ctx = d.certificada()
    return P().ejecutar("O5.Md", S(ctx["r3"]), Objeto("parcela", ctx["parcela"]), servicio="modificar_parcela",
                        parcela_id=ctx["parcela"], wkt=pc.cuadrado(9))


def k49():
    d = Datos()
    ctx = d.base()
    return P().ejecutar("O5.Ba", S(ctx["r3"]), Objeto("parcela", ctx["parcela"]), parcela_id=ctx["parcela"])


def k50():
    d = Datos()
    ctx = d.base()
    return P().decidir("O1.L", S(ctx["r3"]), Objeto("medicion", ctx["medicion"]))


def k51():
    d = Datos()
    ctx = d.base()
    return P().ejecutar("O2.Ci", S(ctx["r7"]), Objeto("periodo", ctx["periodo"]), periodo_id=ctx["periodo"])


def k52():
    d = Datos()
    ctx = d.base()
    servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    return P().ejecutar("O2.Ci", S(ctx["r7"]), Objeto("periodo", ctx["periodo"]), periodo_id=ctx["periodo"])


def decision_pura(operacion, rol_codigo):
    return P().decidir(operacion, S(Datos().usuario(rol_codigo)))


def k53():
    return decision_pura("O2.Ro", "R7")


def k54():
    return decision_pura("O7.MdE", "R4")


def k59():
    return decision_pura("O8.Cf", "R7")


def anular(ctx, justificacion=JUSTIFICACION):
    return P().ejecutar("O3.An", S(ctx["r7"]), Objeto("certificado", ctx["certificado"]),
                        certificado_id=ctx["certificado"], justificacion=justificacion)


def k55():
    return anular(Datos().certificada())


def k56():
    return anular(Datos().certificada(), "   ")


def k67():
    ctx = Datos().certificada()
    with mock.patch.object(servicios, "_registrar_aviso_gerencia", side_effect=RuntimeError("aviso no registrado")):
        salida = anular(ctx)
    vigente = Certificado.objects.filter(pk=ctx["certificado"], estado="vigente").exists()
    return salida, vigente, f"certificado sigue vigente={vigente}"


def k57():
    ctx = Datos().certificada()
    servicios.anular_certificado(ctx["r7"], ctx["certificado"], justificacion=JUSTIFICACION)
    aviso = Alerta.objects.filter(tipo="anulacion_certificado", medicion_id=ctx["medicion"]).values_list("id", flat=True).first()
    return P().ejecutar("O8.Rs", S(ctx["r7"]), Objeto("alerta", aviso), alerta_id=aviso, justificacion=JUSTIFICACION)


def k58():
    d = Datos()
    ctx = d.cerrada()
    d.cambiar_rol(ctx, ctx["tecnico"], "R1", "R2")
    d.actor(ctx["r7"])
    d.afectar("UPDATE mediciones_medicion SET verificador_asignado_id = %s WHERE id = %s", [ctx["tecnico"].pk, ctx["medicion"]])
    return P().ejecutar("O1.Rs", S(ctx["r7"]), Objeto("medicion", ctx["medicion"]), medicion_id=ctx["medicion"],
                        destino_id=ctx["r2"].pk)


def ventanas(d, acumulados: int, nuevos: int, con_solicitud: bool = True):
    r7, r4, r4b, auditor = d.usuario("R7"), d.usuario("R4"), d.usuario("R4"), d.usuario("R5")
    previa = cuentas.solicitar_ventana(r7, auditor.pk, pk.en_2099(1, 1), pk.en_2099(1, 1 + acumulados)).ventana_id
    cuentas.abrir_ventana(r4b, previa)
    nueva = uuid.uuid4()
    if con_solicitud:
        nueva = cuentas.solicitar_ventana(r7, auditor.pk, pk.en_2099(2, 1), pk.en_2099(2, 1 + nuevos)).ventana_id
    return P().ejecutar("O6.Av", S(r4), Objeto("ventana", nueva), ventana_id=nueva)


def k60():
    return ventanas(Datos(), 20, 10)


def k61():
    return ventanas(Datos(), 20, 10, con_solicitud=False)


def k62():
    return ventanas(Datos(), 20, 11)


def k63():
    d = Datos()
    auditor = d.usuario("R5")
    return P().ejecutar("O6.Sv", S(d.usuario("R7")), Objeto("cuenta", auditor.pk), auditor_id=auditor.pk,
                        inicio=pk.en_2099(3, 1), fin=pk.en_2099(3, 5))


def emergencia(autorizador, beneficiario, rol_suplido="R2", perfil="solo_lectura"):
    return P().ejecutar("O6.Ae", S(autorizador), Objeto("cuenta", beneficiario.pk), beneficiario_id=beneficiario.pk,
                        rol_suplido=rol_suplido, perfil=perfil)


def k64():
    d = Datos()
    beneficiario = d.usuario()
    primera = emergencia(d.usuario("R7"), beneficiario)
    salida = emergencia(d.usuario("R4"), beneficiario)
    activa = AccesoEmergencia.objects.filter(beneficiario_id=beneficiario.pk, inicio__isnull=False).exists()
    return salida, primera.permitido and activa, f"primera concedida={primera.permitido}, acceso activo={activa}"


def k65():
    d = Datos()
    r7 = d.usuario("R7")
    return emergencia(r7, r7)


def k66():
    d = Datos()
    return emergencia(d.usuario("R4"), d.usuario(), perfil="aprobar")


def k68():
    d = Datos()
    ps.como_dueno(d)
    ctx = d.presentada()
    ps.cierre_en_el_pasado(d, ctx, 89)
    enmienda = ps.solicitar(ctx).enmienda_id
    cerrado = Periodo.objects.filter(pk=ctx["periodo"]).values_list("cerrado_en", flat=True).get()
    with ps.con_ahora(cerrado + timedelta(days=91)):
        return resolver(ctx, ctx["r7"], enmienda)


def k69():
    d = Datos()
    r3 = d.usuario("R3")
    return P().ejecutar("O5.Cr", S(r3), servicio="crear_finca", nombre="Finca nueva", propietarios=[r3.pk])


CASOS = [
    (1, "R1 O1.Rg parcela asignada, período abierto", "C", "", k01, False),
    (2, "R1 O1.Rg parcela no asignada", "D", "Cd1", k02, False),
    (3, "R1 O1.Rg período cerrado", "D", "Cd5", k03, False),
    (4, "R1 O1.Md borrador propio, período abierto", "C", "", k04, False),
    (5, "R1 O1.Md medición ya presentada", "D", "Cd6", k05, False),
    (6, "Cualquier rol O1.MdC", "D", "defecto", k06, False),
    (7, "R1 O1.L región no asignada, 4 ajenas en la jornada", "C", "", k07, False),
    (8, "R1 O1.L parcela fuera de su región", "D", "Cd22", k08, False),
    (9, "R1 O1.L 12 ajenas en horario laboral", "CR", "Cd9", k09, False),
    (10, "R1 O1.L 25 ajenas en horario laboral", "D", "Cd9", k10, False),
    (11, "R1 O1.L 5 ajenas un sábado", "CR", "Cd9", k11, False),
    (12, "R1 O1.L 8 ajenas un sábado", "D", "Cd9", k12, False),
    (13, "R1 O1.L una más con 100 ajenas en 30 días", "D", "Cd9", k13, False),
    (14, "R2 O1.Ap presentada, cerrada, de otra persona", "C", "", k14, False),
    (15, "R2 O1.Ap medición que él registró (historial de roles)", "D", "Cd8", k15, False),
    (16, "R2 O1.Ap sin segundo factor", "D", "Cd4", k16, False),
    (17, "R2 O1.Ap período abierto", "D", "Cd7", k17, False),
    (18, "R2 O1.Ap medición en borrador", "D", "Cd7", k18, False),
    (19, "R2 O1.Ap huella distinta", "D", "Cd7", k19, False),
    (20, "R2 O1.Ap bitácora no disponible", "D", "Cd8", k20, False),
    (21, "R2 O1.Ap certificado vigente para (U, P)", "D", "Cd10", k21, False),
    (22, "R2 O1.Ap segunda aprobación de más de 500 t, mismo aprobador", "D", "Cd8", k22, False),
    (23, "R2 O1.Ap segunda aprobación de más de 500 t, otro verificador", "C", "", k23, False),
    (24, "R2 O1.Dv presentada, período cerrado", "C", "", k24, False),
    (25, "R1 O4.So a los 10 días del cierre", "C", "", k25, False),
    (26, "R1 O4.So a los 120 días del cierre", "D", "Cd11", k26, False),
    (27, "R1 O4.So a los 120 días con certificado anulado", "C", "", k27, False),
    (28, "R7 O4.Au personas distintas", "C", "", k28, False),
    (29, "R7 O4.Au aprobador original (hoy R7)", "D", "Cd12", k29, False),
    (30, "R7 O4.Au solicitada fuera de 90 días con certificado vigente", "D", "Cd12", k30, True),
    (31, "R6 O3.L certificado de una finca de la que es copropietario", "C", "", k31, False),
    (32, "R6 O3.L certificado de otro dueño", "D", "Cd2", k32, False),
    (33, "R6 O1.Md", "D", "defecto", k33, False),
    (34, "R6 O3.Ex su propio certificado", "C", "", k34, False),
    (35, "R5 O1.L dentro de su ventana", "C", "", k35, False),
    (36, "R5 O1.L fuera de su ventana", "D", "Cd3", k36, False),
    (37, "R5 O3.Ex sin segundo factor", "D", "Cd4", k37, False),
    (38, "R5 O1.Md", "D", "defecto", k38, False),
    (39, "R2 O1.L 12 parcelas fuera de su cola", "CR", "Cd9", k39, False),
    (40, "R7 O1.L cualquier finca (queda registrado)", "C", "", k40, False),
    (41, "R7 O1.L bitácora no disponible", "D", "Cd17", k41, False),
    (42, "R4 O6.AR par excluyente R1 con R2", "D", "Cd13", k42, False),
    (43, "R4 O6.AR rol sin conflicto a otra persona", "C", "", k43, False),
    (44, "R4 O6.AR rol a sí mismo", "D", "Cd13", k44, False),
    (45, "R3 O5.As técnico con vencimiento y aviso", "C", "", k45, False),
    (46, "R3 O5.As parcela a sí mismo", "D", "Cd14", k46, False),
    (47, "R3 O5.Md solo propietarios con certificado vigente", "C", "", k47, False),
    (48, "R3 O5.Md límites con certificado vigente", "D", "Cd15", k48, False),
    (49, "R3 O5.Ba parcela con medición en curso", "D", "Cd15", k49, False),
    (50, "R3 O1.L", "D", "defecto", k50, False),
    (51, "R7 O2.Ci período abierto con segundo factor", "C", "", k51, False),
    (52, "R7 O2.Ci período ya cerrado", "D", "Cd5", k52, False),
    (53, "R7 O2.Ro", "D", "defecto", k53, False),
    (54, "R4 O7.MdE", "D", "defecto", k54, False),
    (55, "R7 O3.An certificado vigente con justificación", "C", "", k55, False),
    (56, "R7 O3.An sin justificación", "D", "Cd20", k56, False),
    (57, "R7 O8.Rs alerta de su propia cuenta", "D", "Cd18", k57, False),
    (58, "R7 O1.Rs el único verificador es quien registró", "C", "", k58, False),
    (59, "R7 O8.Cf", "D", "defecto", k59, False),
    (60, "R4 O6.Av solicitud de R7 y 20 días acumulados", "C", "", k60, False),
    (61, "R4 O6.Av sin solicitud", "D", "Cd23", k61, False),
    (62, "R4 O6.Av más de 30 días en el año", "D", "Cd23", k62, False),
    (63, "R7 O6.Sv", "C", "", k63, False),
    (64, "R4 O6.Ae con las dos autorizaciones distintas", "C", "", k64, False),
    (65, "R7 O6.Ae para sí mismo", "D", "Cd24", k65, False),
    (66, "R4 O6.Ae perfil que incluye aprobar", "D", "Cd24", k66, False),
    (67, "R7 O3.An aviso a gerencia que no se puede registrar", "D", "Cd20", k67, False),
    (68, "R7 O4.Au a los 91 días una solicitud de los 89", "C", "", k68, True),
    (69, "R3 O5.Cr agregándose como propietario", "D", "Cd14", k69, False),
    (70, "R4 O6.AR R3 a quien tiene R2", "D", "Cd13", k70, False),
]


def caso(n, esperado, regla, funcion):
    def prueba():
        salida = funcion()
        extra_ok, detalle = True, ""
        if isinstance(salida, tuple):
            salida, extra_ok, detalle = salida
        obtenido, razon = clasificar(salida)
        ok = obtenido == esperado and (razon == regla or esperado == "C") and extra_ok
        texto = f"{obtenido} {razon}".strip()
        return ok, f"{texto}; {detalle}" if detalle else texto
    return prueba


# --------------------------------------------------------------------------- fail-closed, emergencia y Cd2


def f01():
    d = Datos()
    caido = pep.PEP(bitacora=BitacoraEnMemoria(), pdp=pdp.ClienteOPA(f"http://127.0.0.1:{puerto_libre()}"))
    r7 = d.usuario("R7")
    lectura = caido.decidir("O8.L", S(r7))
    escritura = caido.ejecutar("O2.Ab", S(r7), inicio=ps.INICIO, fin=ps.FIN)
    ok = isinstance(lectura, pep.Denegado) and isinstance(escritura, pep.Denegado) and not Periodo.objects.filter(inicio=ps.INICIO).exists()
    return ok, f"lectura {getattr(lectura, 'condicion', '-')}; escritura {getattr(escritura, 'condicion', '-')}"


def f02():
    d = Datos()
    with mock.patch.object(pip, "reunir", side_effect=RuntimeError("PIP caído")):
        salida = P().decidir("O8.L", S(d.usuario("R7")))
    return isinstance(salida, pep.Denegado) and salida.condicion == "defecto", clasificar(salida)[1]


def f03():
    d = Datos()
    ENTORNO.bitacora.fallar_registro = True
    salida = P().ejecutar("O2.Ab", S(d.usuario("R7")), inicio=ps.INICIO, fin=ps.FIN)
    sin_periodo = not Periodo.objects.filter(inicio=ps.INICIO, fin=ps.FIN).exists()
    return isinstance(salida, pep.Denegado) and sin_periodo, f"{clasificar(salida)}; sin período creado={sin_periodo}"


def f04():
    d = Datos()
    ctx = d.lectura_ajena("R1")
    sesion = S(ctx["sujeto"])
    propia = Datos.base(d, ctx={**ctx, "indice": 2})
    catalogo.asignar_tecnico(ctx["r3"], propia["parcela"], ctx["sujeto"].pk, hora_de_la_base() + timedelta(days=30))
    exportable = d.certificada(ctx={**d.finca(), "indice": 7})
    with mock.patch.object(pip, "_contar_ajenas", side_effect=RuntimeError("contadores no disponibles")):
        habitual = P().decidir("O1.L", sesion, Objeto("medicion", propia["medicion"]))
        ajena = P().decidir("O1.L", sesion, Objeto("medicion", ctx["medicion"]))
        exportar = P().ejecutar("O3.Ex", S(exportable["propietarios"][0]), Objeto("certificado", exportable["certificado"]),
                                certificado_id=exportable["certificado"])
    resultados = [clasificar(habitual)[0], clasificar(ajena), clasificar(exportar)]
    ok = resultados == ["C", ("D", "Cd9"), ("D", "Cd9")]
    return ok, f"habitual {resultados[0]}; ajena {resultados[1][1]}; exportación {resultados[2][1]}"


def f05():
    d = Datos()
    ctx = d.cerrada()
    try:
        aprobar(ctx, ctx["r2"], sesion=S(ctx["r2"], edad=3600))
    except pep.ReautenticacionRequerida:
        sin_aprobar = Medicion.objects.filter(pk=ctx["medicion"]).values_list("estado", flat=True).get() == "presentada"
        return sin_aprobar, f"ReautenticacionRequerida; medición sin aprobar={sin_aprobar}"
    return False, "sin reautenticación"


def g01():
    d = Datos()
    # La RLS de la base no conoce el acceso de emergencia: el beneficiario necesita un rol propio con
    # lectura (aquí R1) para que la base le muestre filas; la política decide solo con el rol suplido.
    beneficiario = d.usuario("R1")
    cuentas.autorizar_emergencia(d.usuario("R4"), beneficiario.pk, "R2")
    cuentas.autorizar_emergencia(d.usuario("R7"), beneficiario.pk, "R2")
    ctx = d.presentada()
    sesion = S(beneficiario)
    lectura = P().decidir("O1.L", sesion, Objeto("medicion", ctx["medicion"]))
    consumida = sesion.emergencia is not None and sesion.emergencia["rol_suplido"] == "R2"
    negadas = {
        "aprobar": aprobar(ctx, beneficiario, sesion=sesion),
        "exportar": P().ejecutar("O3.Ex", sesion, Objeto("certificado", uuid.uuid4()), certificado_id=uuid.uuid4()),
        "cuentas": P().decidir("O6.L", sesion),
        "bitacora": P().decidir("O7.L", sesion),
    }
    todas = all(clasificar(s) == ("D", "Cd24") for s in negadas.values())
    segundo = ps.condicion(lambda: cuentas.consumir_emergencia(beneficiario.pk))
    nueva = P().decidir("O1.L", S(beneficiario), Objeto("medicion", ctx["medicion"]))
    sesion.emergencia = {**sesion.emergencia, "vence_en": (hora_de_la_base() - timedelta(minutes=1)).isoformat()}
    vencida = P().decidir("O1.L", sesion, Objeto("medicion", ctx["medicion"]))
    # Sin el perfil, el beneficiario decide con su propio R1, que no tiene esa parcela en su región.
    ok = (clasificar(lectura)[0] == "C" and consumida and todas and segundo == "Cd24"
          and clasificar(nueva) == ("D", "Cd22") and clasificar(vencida) == ("D", "Cd22"))
    return ok, (f"lee {clasificar(lectura)[0]}; escribir, exportar, cuentas y bitácora Cd24={todas}; segundo uso {segundo};"
                f" otra sesión {clasificar(nueva)[1]}; vencida {clasificar(vencida)[1]}")


def h01():
    d = Datos()
    ctx = certificado_de_finca(d)
    ajeno = d.usuario("R6")
    salidas = [P().decidir("O3.L", S(ajeno), Objeto("certificado", ctx["certificado"])) for _ in range(3)]
    alertas = Alerta.objects.filter(tipo=pep.TIPO_DENEGACIONES_CD2, usuario_id=ajeno.pk).count()
    ok = all(clasificar(s) == ("D", "Cd2") for s in salidas) and alertas == 1
    return ok, f"3 denegaciones Cd2; alertas a R7={alertas}"


# --------------------------------------------------------------------------- barrido


def barrido(opa, python) -> tuple[int, int, list[str]]:
    """Celda por celda con todo satisfecho, y cada condición de política violada por separado."""
    def entrada(op, rol, cambios=None):
        return {"sujeto": {"id": "0123456789abcdef", "roles": [rol], "emergencia": None}, "operacion": op,
                "hechos": {**TODOS, **(cambios or {})}, "parametros": PARAMETROS}

    errores: list[str] = []
    decisiones = 0
    permitidas = 0
    politica = set(motor.matriz()["condiciones_politica"])
    for op, porrol in motor.matriz()["operaciones"].items():
        for rol in motor.matriz()["roles"]:
            a, b = opa.decidir(entrada(op, rol)), python.decidir(entrada(op, rol))
            decisiones += 1
            permitidas += a["permitir"]
            if a != b:
                errores.append(f"paridad {op} {rol}")
            if a["permitir"] != (rol in porrol):
                errores.append(f"matriz {op} {rol}")
        for rol, conds in porrol.items():
            for c in (c for c in conds if c in politica):
                cambio = ({"h2": {"disponible": True, "ajena": True, "wc": 100, "wl": 100, "laboral": True}}
                          if c == "Cd9" else {motor.HECHOS[c]: False})
                a, b = opa.decidir(entrada(op, rol, cambio)), python.decidir(entrada(op, rol, cambio))
                decisiones += 1
                if a != b:
                    errores.append(f"paridad {op} {rol} {c}")
                if a["permitir"] or a["razon"] != c:
                    errores.append(f"violación {op} {rol} {c}")
    return decisiones, permitidas, errores


# --------------------------------------------------------------------------- ejecución


def conteo_accesos() -> int:
    conexion = psycopg.connect(os.environ[ps.MIGRADOR], connect_timeout=15)
    try:
        conexion.execute("SET lock_timeout = '10s'")
        conexion.execute(f"ALTER TABLE {TABLA_ACCESOS} NO FORCE ROW LEVEL SECURITY")
        return conexion.execute(f"SELECT count(*) FROM {TABLA_ACCESOS}").fetchone()[0]
    finally:
        conexion.rollback()
        conexion.close()


def conteos() -> dict[str, int]:
    original = ps.TABLAS_CONTEO
    ps.TABLAS_CONTEO = pk.TABLAS_CONTEO
    try:
        totales = ps.conteos()
    finally:
        ps.TABLAS_CONTEO = original
    totales[TABLA_ACCESOS] = conteo_accesos()
    return totales


def main() -> int:
    global ENTORNO
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    proceso, url = iniciar_opa()
    try:
        opa, python = pdp.ClienteOPA(url), pdp.MotorPython()
        decisiones, permitidas, errores_barrido = barrido(opa, python)
        ENTORNO = Entorno(Comparador(opa, python))
        ps.usar(ps.APP)
        iniciales = conteos()
        resultados = []
        for n, descripcion, esperado, regla, funcion, como_migrador in CASOS:
            ENTORNO.reiniciar()
            if como_migrador:
                ps.usar(ps.MIGRADOR)
            try:
                etiqueta = f"{esperado} {regla}".strip()
                resultados.append(ps.ejecutar(f"{n:02d}", descripcion, etiqueta, caso(n, esperado, regla, funcion)))
            finally:
                if como_migrador:
                    ps.usar(ps.APP)
        extras = [
            ("F01", "OPA caído deniega lectura y escritura", "D, D", f01),
            ("F02", "PIP con error deniega", "D defecto", f02),
            ("F03", "Registro del intento fallido deniega", "D, sin efecto", f03),
            ("F04", "Cd9 degradado: habitual concede, ajena y exportación deniegan", "C; Cd9; Cd9", f04),
            ("F05", "Acción crítica sin segundo factor reciente", "ReautenticacionRequerida", f05),
            ("G01", "Emergencia: lee con el rol suplido; no escribe ni exporta; un solo uso; vence", "C; Cd24; no concede", g01),
            ("H01", "Tres denegaciones Cd2 en 24 horas avisan a R7", "1 alerta", h01),
        ]
        for id_, descripcion, esperado, funcion in extras:
            ENTORNO.reiniciar()
            resultados.append(ps.ejecutar(id_, descripcion, esperado, funcion))
        finales = conteos()
    finally:
        ps.connections["default"].close()
        proceso.terminate()
        proceso.wait(timeout=10)
    pm.imprimir_tabla(resultados)
    casos = [r for r in resultados if r.id.isdigit()]
    por_resultado = {e: sum(1 for (_, _, esp, *_), r in zip(CASOS, casos) if esp == e and r.ok) for e in ("C", "CR", "D")}
    esperados = {e: sum(1 for c in CASOS if c[2] == e) for e in ("C", "CR", "D")}
    print(f"\nBarrido: {decisiones} decisiones por backend, {permitidas} permitidas, errores={len(errores_barrido)}")
    for error in errores_barrido[:10]:
        print(f"  [FALLO] {error}")
    print(f"70 casos: {sum(r.ok for r in casos)}/{len(casos)} OK; por resultado (OK/esperados):"
          f" C {por_resultado['C']}/{esperados['C']}, CR {por_resultado['CR']}/{esperados['CR']}, D {por_resultado['D']}/{esperados['D']}")
    print(f"Paridad en los casos: {ENTORNO.comparador.comparadas} decisiones comparadas, diferencias={len(ENTORNO.comparador.diferencias)}")
    correctas = sum(r.ok for r in resultados)
    print(f"Total: {correctas}/{len(resultados)} OK")
    limpio = finales == iniciales
    print(f"Conteos antes: {iniciales}")
    print(f"Conteos después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio else "[FALLO] Quedaron datos de prueba.")
    paridad = not ENTORNO.comparador.diferencias and not errores_barrido
    return 0 if correctas == len(resultados) and limpio and paridad else 1


if __name__ == "__main__":
    sys.exit(main())
