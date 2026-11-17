#!/usr/bin/env python3
"""Pruebas de la firma Ed25519 de certificados: módulo, validación en la base, rutas y verificador.

Uso (con el entorno de pruebas cargado):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_firma.py
    python scripts/probar_firma.py --exportar DIR   # DIR fuera del repositorio

Las pruebas de base corren como app_rw en transacciones que siempre se revierten. Nunca imprime la
clave de firma, firmas completas ni payloads.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "scripts"))

import probar_mediciones as pm  # noqa: E402
import verify_cert  # noqa: E402
from mediciones import firma  # noqa: E402

LIMITE_BYTES = 65536
HOST = "localhost"


def resultado(ok: bool, obtenido: str):
    return ok, obtenido


def payload_sintetico(clave: Ed25519PrivateKey | None = None) -> dict:
    """Payload con datos ficticios, para pruebas que no tocan la base."""
    return firma.construir_payload(
        uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 1, "123.4", "a" * 64,
        [uuid.uuid4(), uuid.uuid4()], datetime.now(timezone.utc), clave=clave,
    )


def copia(documento: dict) -> dict:
    return json.loads(json.dumps(documento))


def cambiar_byte_b64(valor: str) -> str:
    datos = bytearray(base64.b64decode(valor))
    datos[0] ^= 0x01
    return base64.b64encode(bytes(datos)).decode("ascii")


@contextmanager
def entorno_de_clave(valor: str | None):
    """Cambia CERT_SIGNING_KEY temporalmente y limpia la caché de la clave; restaura al salir."""
    original = os.environ.get(firma.VARIABLE_CLAVE)
    try:
        if valor is None:
            os.environ.pop(firma.VARIABLE_CLAVE, None)
        else:
            os.environ[firma.VARIABLE_CLAVE] = valor
        firma.clave_privada.cache_clear()
        yield
    finally:
        if original is None:
            os.environ.pop(firma.VARIABLE_CLAVE, None)
        else:
            os.environ[firma.VARIABLE_CLAVE] = original
        firma.clave_privada.cache_clear()


# --------------------------------------------------------------------------- módulo (sin base)


def f01(app, mig):
    clave = Ed25519PrivateKey.generate()
    documento = firma.firmar(payload_sintetico(clave), clave)
    estado = firma.verificar(documento, firma.huella_publica(clave)).estado
    return resultado(estado == firma.ESTADO_VALIDO, estado)


def f02(app, mig):
    clave = Ed25519PrivateKey.generate()
    documento = copia(firma.firmar(payload_sintetico(clave), clave))
    documento["payload"]["co2e_toneladas"] = "999.000"
    estado = firma.verificar(documento, firma.huella_publica(clave)).estado
    return resultado(estado == firma.ESTADO_FIRMA_INVALIDA, estado)


def f03(app, mig):
    clave = Ed25519PrivateKey.generate()
    documento = copia(firma.firmar(payload_sintetico(clave), clave))
    documento["signature"] = cambiar_byte_b64(documento["signature"])
    estado = firma.verificar(documento, firma.huella_publica(clave)).estado
    return resultado(estado == firma.ESTADO_FIRMA_INVALIDA, estado)


def f04(app, mig):
    clave, otra = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    documento = copia(firma.firmar(payload_sintetico(clave), clave))
    documento["public_key"] = firma.clave_publica_b64(otra)
    estado = firma.verificar(documento, firma.huella_publica(clave)).estado
    return resultado(estado == firma.ESTADO_FIRMA_INVALIDA, estado)


def f05(app, mig):
    confiable, ajena = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    documento = firma.firmar(payload_sintetico(ajena), ajena)
    estado = firma.verificar(documento, firma.huella_publica(confiable)).estado
    return resultado(estado == firma.ESTADO_CLAVE_NO_CONFIABLE, estado)


def f06(app, mig):
    clave = Ed25519PrivateKey.generate()
    base_doc = firma.firmar(payload_sintetico(clave), clave)
    huella = firma.huella_publica(clave)
    variantes = {}
    sin_campo = copia(base_doc)
    del sin_campo["payload"]["aprobadores"]
    variantes["campo faltante"] = sin_campo
    otro_alg = copia(base_doc)
    otro_alg["alg"] = "RS256"
    variantes["alg distinto"] = otro_alg
    mal_b64 = copia(base_doc)
    mal_b64["signature"] = "esto-no-es-base64!"
    variantes["base64 inválido"] = mal_b64
    corta = copia(base_doc)
    corta["public_key"] = base64.b64encode(b"\x00" * 31).decode("ascii")
    variantes["longitud incorrecta"] = corta
    tipo = copia(base_doc)
    tipo["payload"]["medicion_numero"] = "1"
    variantes["tipo incorrecto"] = tipo
    estados = {nombre: firma.verificar(doc, huella).estado for nombre, doc in variantes.items()}
    ok = all(e == firma.ESTADO_FORMATO_INVALIDO for e in estados.values())
    return resultado(ok, "; ".join(f"{k} {v}" for k, v in estados.items()))


def f07(app, mig):
    clave = Ed25519PrivateKey.generate()
    estado = firma.verificar(firma.firmar(payload_sintetico(clave), clave), None).estado
    return resultado(estado == firma.ESTADO_SIN_CONFIANZA, estado)


def f08(app, mig):
    invalidos = {
        "ausente": None,
        "vacía": "   ",
        "16 bytes": base64.b64encode(os.urandom(16)).decode("ascii"),
        "no base64": "no-es-base64-valido!!",
    }
    obtenidos = []
    for nombre, valor in invalidos.items():
        with entorno_de_clave(valor):
            try:
                firma.huella_publica()
                obtenidos.append((nombre, "sin error", False))
            except firma.ClaveDeFirmaNoConfigurada as error:
                filtra = bool(valor and valor.strip()) and valor.strip() in str(error)
                obtenidos.append((nombre, "error claro", not filtra))
    ok = all(limpio and texto == "error claro" for _, texto, limpio in obtenidos)
    return resultado(ok, "; ".join(f"{n}: {t}, sin filtrar valor={l}" for n, t, l in obtenidos))


def f09(app, mig):
    entradas = [
        payload_sintetico(),
        {"b": 1, "a": [3, 2, 1], "c": {"z": "ñandú", "y": None, "x": True}},
        {"texto": "áéíóú ü   \"comillas\" \\barra", "numero": 12345678901234567890, "lista": []},
    ]
    iguales = all(firma.canonico(e) == verify_cert.canonico(e) for e in entradas)
    clave = Ed25519PrivateKey.generate()
    documento = firma.firmar(payload_sintetico(clave), clave)
    huella = firma.huella_publica(clave)
    coinciden = firma.verificar(documento, huella).estado == verify_cert.verificar(documento, huella)
    return resultado(iguales and coinciden, f"bytes idénticos={iguales}, mismo estado al verificar={coinciden}")


# --------------------------------------------------------------------------- base de datos


def emitir_variante(app, alterar_payload=None, columnas=None, segundos_desfase=0) -> str:
    e = pm.Escenario(app)
    ctx = e.aprobada()
    return pm.intento(app, lambda: e.emitir(ctx, ctx["r2"], alterar_payload=alterar_payload,
                                            columnas=columnas, segundos_desfase=segundos_desfase))


def mensaje_de_rechazo(app, **variante) -> str:
    """Mensaje del error de la base, para comprobar que cada discrepancia se distingue."""
    e = pm.Escenario(app)
    ctx = e.aprobada()
    app.execute("SAVEPOINT mensaje")
    try:
        e.emitir(ctx, ctx["r2"], **variante)
    except Exception as error:  # noqa: BLE001 - solo se usa el texto del error de la base
        app.execute("ROLLBACK TO SAVEPOINT mensaje")
        return getattr(getattr(error, "diag", None), "message_primary", "") or ""
    return ""


DISCREPANCIAS = {
    "certificado_id": {"alterar_payload": {"certificado_id": str(uuid.uuid4())}},
    "parcela_id": {"alterar_payload": {"parcela_id": str(uuid.uuid4())}},
    "periodo_id": {"alterar_payload": {"periodo_id": str(uuid.uuid4())}},
    "medicion_id": {"alterar_payload": {"medicion_id": str(uuid.uuid4())}},
    "medicion_numero": {"alterar_payload": {"medicion_numero": 99}},
    "co2e_toneladas": {"alterar_payload": {"co2e_toneladas": "999.000"}},
    "huella_medicion": {"alterar_payload": {"huella_medicion": "0" * 64}},
    "aprobadores": {"alterar_payload": {"aprobadores": ["0" * 16]}},
    "version_politica vacía": {"alterar_payload": {"version_politica": ""}},
    "payload.key_id": {"alterar_payload": {"key_id": "0" * 16},
                       "columnas": {"key_id": firma.key_id(pm.CLAVE_PRUEBA)}},
    "key_id de la columna": {"columnas": {"key_id": "0" * 16}},
    "alg distinto": {"columnas": {"alg": "RS256"}},
    "fecha a 120 s": {"segundos_desfase": -120},
}


def b01(app, mig):
    obtenido = emitir_variante(app)
    return resultado(obtenido == pm.PASA, obtenido)


def pruebas_discrepancias(app, mig) -> list[tuple[str, str, str, bool, str]]:
    filas = []
    for numero, (nombre, variante) in enumerate(DISCREPANCIAS.items(), start=2):
        obtenido = emitir_variante(app, **variante)
        filas.append((f"B{numero:02d}", f"Inserción con {nombre} discrepante", pm.INTEGRIDAD,
                      obtenido == pm.INTEGRIDAD, obtenido))
        app.connection.rollback()
    return filas


def b15(app, mig):
    mensajes = {}
    for nombre, variante in DISCREPANCIAS.items():
        mensajes[nombre] = mensaje_de_rechazo(app, **variante)
        app.connection.rollback()
    distintos = len(set(mensajes.values())) == len(mensajes) and all(mensajes.values())
    return resultado(distintos, f"{len(set(mensajes.values()))} mensajes distintos para {len(mensajes)} casos")


def b16(app, mig):
    e = pm.Escenario(app)
    ctx = e.certificada()
    e.actor(ctx["r7"])
    obtenidos = {}
    for columna, valor in (("payload", "'{}'::jsonb"), ("firma", "'x'"), ("clave_publica", "'x'"),
                           ("key_id", "'0000000000000000'"), ("alg", "'Ed25519'")):
        obtenidos[columna] = pm.intento(app, lambda c=columna, v=valor: app.execute(
            f"UPDATE mediciones_certificado SET {c} = {v} WHERE id = %s", (ctx["certificado"],)))
    ok = all(v == pm.SIN_PERMISO for v in obtenidos.values())
    return resultado(ok, ", ".join(f"{k} {v}" for k, v in obtenidos.items()))


# --------------------------------------------------------------------------- rutas


def _django():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    import django

    django.setup()
    from django.test import Client

    return Client


def documento_real() -> dict:
    return firma.firmar(payload_sintetico())


def pruebas_rutas(app, mig) -> list[tuple[str, str, str, bool, str]]:
    Client = _django()
    cliente = Client(HTTP_HOST=HOST)
    estricto = Client(HTTP_HOST=HOST, enforce_csrf_checks=True)
    filas = []

    r = cliente.get("/certificados/clave-publica/")
    datos = r.json() if r.status_code == 200 else {}
    ok = (r.status_code == 200 and datos.get("alg") == "Ed25519" and datos.get("huella_sha256") == firma.huella_publica()
          and datos.get("key_id") == firma.key_id() and datos.get("public_key") == firma.clave_publica_b64())
    filas.append(("W01", "GET /certificados/clave-publica/", "200 con alg, clave, huella y key_id", ok,
                  f"HTTP {r.status_code}, campos {sorted(datos)}"))

    r = cliente.get("/verificar/")
    contenido = r.content.decode()
    ok = r.status_code == 200 and "<textarea" in contenido and "csrfmiddlewaretoken" in contenido
    filas.append(("W02", "GET /verificar/", "200 con formulario y CSRF", ok, f"HTTP {r.status_code}"))

    texto = json.dumps(documento_real())
    r = cliente.post("/verificar/", {"certificado": texto})
    sin_token = estricto.post("/verificar/", {"certificado": texto})
    ok = r.status_code == 200 and "Estado: valido" in r.content.decode() and sin_token.status_code == 403
    filas.append(("W03", "POST /verificar/ válido; sin token CSRF se rechaza", "200 valido; 403", ok,
                  f"HTTP {r.status_code}; sin token HTTP {sin_token.status_code}"))

    r = estricto.post("/api/verificar/", data=texto, content_type="application/json")
    cuerpo = r.json() if r.status_code == 200 else {}
    ok = r.status_code == 200 and cuerpo.get("estado") == firma.ESTADO_VALIDO
    filas.append(("W04", "POST /api/verificar/ válido sin token CSRF (exenta)", "200 valido", ok,
                  f"HTTP {r.status_code}, estado {cuerpo.get('estado')}"))

    alterado = copia(documento_real())
    alterado["payload"]["co2e_toneladas"] = "999.000"
    r = cliente.post("/api/verificar/", data=json.dumps(alterado), content_type="application/json")
    filas.append(("W05", "POST /api/verificar/ alterado", "200 firma_invalida",
                  r.status_code == 200 and r.json().get("estado") == firma.ESTADO_FIRMA_INVALIDA,
                  f"HTTP {r.status_code}, estado {r.json().get('estado')}"))

    r = cliente.post("/api/verificar/", data="{no es json", content_type="application/json")
    filas.append(("W06", "POST /api/verificar/ con JSON ilegible", "400 formato_invalido",
                  r.status_code == 400 and r.json().get("estado") == firma.ESTADO_FORMATO_INVALIDO,
                  f"HTTP {r.status_code}, estado {r.json().get('estado')}"))

    grande = json.dumps({"relleno": "x" * (LIMITE_BYTES + 10)})
    r = cliente.post("/api/verificar/", data=grande, content_type="application/json")
    filas.append(("W07", "POST /api/verificar/ mayor a 65536 bytes", "413", r.status_code == 413, f"HTTP {r.status_code}"))

    r = cliente.post("/api/verificar/", data=texto, content_type="text/plain")
    filas.append(("W08", "POST /api/verificar/ sin Content-Type JSON", "415", r.status_code == 415, f"HTTP {r.status_code}"))

    r = cliente.get("/api/verificar/")
    filas.append(("W09", "GET /api/verificar/", "405", r.status_code == 405, f"HTTP {r.status_code}"))

    with entorno_de_clave(None):
        codigos = [cliente.get("/certificados/clave-publica/").status_code,
                   cliente.get("/verificar/").status_code,
                   cliente.post("/api/verificar/", data=texto, content_type="application/json").status_code]
        detalle = cliente.get("/certificados/clave-publica/").content.decode()
    ok = codigos == [503, 503, 503] and firma.VARIABLE_CLAVE not in detalle
    filas.append(("W10", "Sin CERT_SIGNING_KEY las tres rutas responden 503 sin detalles", "503 x3", ok, f"HTTP {codigos}"))
    return filas


# --------------------------------------------------------------------------- exportación


def exportar(directorio: str) -> int:
    destino = Path(directorio).resolve()
    try:
        destino.relative_to(RAIZ)
        print("[FALLO] El directorio de exportación no puede estar dentro del repositorio.")
        return 2
    except ValueError:
        pass
    destino.mkdir(parents=True, exist_ok=True)
    valido = documento_real()
    alterado = copia(valido)
    alterado["payload"]["co2e_toneladas"] = "999.000"
    ajena = Ed25519PrivateKey.generate()
    clave_ajena = firma.firmar(payload_sintetico(ajena), ajena)
    malformado = copia(valido)
    del malformado["signature"]
    archivos = {"valido.json": valido, "alterado.json": alterado, "clave_ajena.json": clave_ajena,
                "malformado.json": malformado}
    for nombre, documento in archivos.items():
        (destino / nombre).write_text(json.dumps(documento, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] {len(archivos)} certificados exportados: {', '.join(archivos)}")
    print(f"Huella pública confiable: {firma.huella_publica()}")
    return 0


# --------------------------------------------------------------------------- ejecución

PRUEBAS = [
    ("F01", "Ida y vuelta con huella confiable", firma.ESTADO_VALIDO, f01),
    ("F02", "Payload alterado tras firmar", firma.ESTADO_FIRMA_INVALIDA, f02),
    ("F03", "Firma alterada", firma.ESTADO_FIRMA_INVALIDA, f03),
    ("F04", "Clave pública cambiada sin volver a firmar", firma.ESTADO_FIRMA_INVALIDA, f04),
    ("F05", "Clave ajena y documento refirmado", firma.ESTADO_CLAVE_NO_CONFIABLE, f05),
    ("F06", "Campo faltante, alg distinto, base64 inválido, longitud y tipo incorrectos", "formato_invalido x5", f06),
    ("F07", "Sin huella confiable", firma.ESTADO_SIN_CONFIANZA, f07),
    ("F08", "CERT_SIGNING_KEY ausente, vacía, corta o no base64", "error claro sin el valor", f08),
    ("F09", "Canonicalización idéntica en firma.py y verify_cert.py", "bytes idénticos", f09),
    ("B01", "Inserción con payload correcto", pm.PASA, b01),
    ("DISCREPANCIAS", "", "", pruebas_discrepancias),
    ("B15", "Cada discrepancia produce un mensaje distinto", "13 mensajes distintos", b15),
    ("B16", "app_rw no actualiza payload, firma, clave_publica, key_id ni alg", "42501 x5", b16),
    ("B17", "Segundo certificado vigente contra el índice único (sin disparadores, migrador)", pm.UNICIDAD, pm.c04b),
    ("RUTAS", "", "", pruebas_rutas),
]


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(description="Pruebas de la firma Ed25519 de certificados.")
    parser.add_argument("--exportar", metavar="DIR", help="escribe certificados de prueba en DIR (fuera del repo)")
    args = parser.parse_args()
    try:
        firma.huella_publica()
    except firma.ClaveDeFirmaNoConfigurada as error:
        print(f"[FALLO] {error} Cargue antes: . .\\scripts\\entorno_dev.ps1 -Pruebas")
        return 2
    if args.exportar:
        return exportar(args.exportar)
    conexiones = {rol: pm.conectar(rol) for rol in pm.VARIABLES_CONEXION}
    try:
        iniciales = pm.conteos(conexiones[pm.APP])
        resultados = []
        for id_, descripcion, esperado, funcion in PRUEBAS:
            resultados.extend(pm.ejecutar(conexiones, id_, descripcion, esperado, funcion))
        finales = pm.conteos(conexiones[pm.APP])
    finally:
        for conexion in conexiones.values():
            conexion.rollback()
            conexion.close()
    pm.imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    print(f"\nTotal: {correctas}/{len(resultados)} OK")
    limpio = finales == iniciales
    print("[OK] No quedaron datos de prueba." if limpio else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio else 1


if __name__ == "__main__":
    sys.exit(main())
