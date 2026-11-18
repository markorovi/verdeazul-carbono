#!/usr/bin/env python3
"""Verificador independiente de certificados Verdeazul Carbono (Ed25519).

Uso:
    python scripts/verificar_certificado.py ARCHIVO.json [--huella HEX64]

La huella esperada es el SHA-256 (hex) de la clave pública del emisor, publicada en /clave-publica/
y en /certificados/clave-publica/. Solo depende de la biblioteca estándar y de cryptography: no
importa nada del proyecto y se puede entregar suelto a un tercero.

Resultados y códigos de salida:
    0 integro_emisor_esperado  firma válida y la clave es la de la huella esperada
    1 integro_otra_clave       firma válida, pero con otra clave
    2 alterado                 la firma no corresponde al contenido
    3 formato_invalido         documento ilegible o incompleto, o --huella mal formada
    4 integro_sin_huella       firma válida; sin --huella no se puede confirmar el emisor

Acepta el certificado solo o el archivo completo de la exportación ({"certificado", "estado",
"trazabilidad"}). En el segundo caso se verifica únicamente el objeto certificado, con los mismos
códigos, y se imprime una segunda línea que lo indica: estado y trazabilidad no están firmados.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LIMITE_BYTES = 65536
ALG = "Ed25519"
CAMPOS_DOCUMENTO = {"payload", "signature", "public_key", "alg"}
CAMPOS_ENVOLTORIO = {"certificado", "estado", "trazabilidad"}
AVISO_ENVOLTORIO = "Se verifico el objeto certificado; estado y trazabilidad no estan firmados."
CAMPOS_PAYLOAD = {
    "certificado_id",
    "parcela_id",
    "periodo_id",
    "medicion_id",
    "medicion_numero",
    "co2e_toneladas",
    "huella_medicion",
    "aprobadores",
    "fecha_emision",
    "version_politica",
    "key_id",
}
# Estado interno (el mismo de mediciones.firma.verificar) -> (resultado, código de salida).
RESULTADOS = {
    "valido": ("integro_emisor_esperado", 0),
    "clave_no_confiable": ("integro_otra_clave", 1),
    "firma_invalida": ("alterado", 2),
    "formato_invalido": ("formato_invalido", 3),
    "sin_confianza_establecida": ("integro_sin_huella", 4),
}
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_CO2E = re.compile(r"^[0-9]+\.[0-9]{3}$")
_FECHA = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def canonico(obj) -> bytes:
    """Idéntica a mediciones.firma.canonico."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _b64(valor, largo: int) -> bytes | None:
    if not isinstance(valor, str):
        return None
    try:
        datos = base64.b64decode(valor, validate=True)
    except (binascii.Error, ValueError):
        return None
    return datos if len(datos) == largo else None


def _payload_valido(payload) -> bool:
    if not isinstance(payload, dict) or set(payload) != CAMPOS_PAYLOAD:
        return False
    if not all(isinstance(payload[c], str) and _UUID.match(payload[c])
               for c in ("certificado_id", "parcela_id", "periodo_id", "medicion_id")):
        return False
    numero = payload["medicion_numero"]
    if isinstance(numero, bool) or not isinstance(numero, int) or numero < 1:
        return False
    aprobadores = payload["aprobadores"]
    return (
        isinstance(payload["co2e_toneladas"], str) and bool(_CO2E.match(payload["co2e_toneladas"]))
        and isinstance(payload["huella_medicion"], str) and bool(_HEX64.match(payload["huella_medicion"]))
        and isinstance(aprobadores, list) and all(isinstance(a, str) and _HEX16.match(a) for a in aprobadores)
        and isinstance(payload["fecha_emision"], str) and bool(_FECHA.match(payload["fecha_emision"]))
        and isinstance(payload["version_politica"], str) and bool(payload["version_politica"])
        and isinstance(payload["key_id"], str) and bool(_HEX16.match(payload["key_id"]))
    )


def objeto_a_verificar(documento):
    """Idéntica a mediciones.firma.objeto_a_verificar: del archivo exportado devuelve su certificado;
    cualquier otra forma vuelve sin cambios y verificar() decide."""
    if (isinstance(documento, dict) and set(documento) == CAMPOS_ENVOLTORIO
            and isinstance(documento["certificado"], dict)):
        return documento["certificado"]
    return documento


def verificar(documento, huella_confiable: str | None) -> str:
    """Mismo orden que mediciones.firma.verificar: formato, firma y confianza."""
    if not isinstance(documento, dict) or set(documento) != CAMPOS_DOCUMENTO or documento["alg"] != ALG:
        return "formato_invalido"
    if not _payload_valido(documento["payload"]):
        return "formato_invalido"
    firma = _b64(documento["signature"], 64)
    publica = _b64(documento["public_key"], 32)
    if firma is None or publica is None:
        return "formato_invalido"
    try:
        clave = Ed25519PublicKey.from_public_bytes(publica)
    except ValueError:
        return "formato_invalido"
    try:
        clave.verify(firma, canonico(documento["payload"]))
    except InvalidSignature:
        return "firma_invalida"
    if huella_confiable is None:
        return "sin_confianza_establecida"
    if hashlib.sha256(publica).hexdigest() != huella_confiable.strip().lower():
        return "clave_no_confiable"
    return "valido"


def leer_documento(ruta: str):
    """Lee a lo sumo LIMITE_BYTES; un archivo mayor o ilegible es formato_invalido."""
    try:
        with open(ruta, "rb") as archivo:
            datos = archivo.read(LIMITE_BYTES + 1)
    except OSError:
        return None
    if len(datos) > LIMITE_BYTES:
        return None
    try:
        return json.loads(datos.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verifica un certificado Verdeazul Carbono firmado con Ed25519.")
    parser.add_argument("archivo")
    parser.add_argument("--huella", help="SHA-256 (64 hex) de la clave pública esperada")
    args = parser.parse_args(argv)
    if args.huella is not None and not _HEX64.match(args.huella.strip().lower()):
        print("formato_invalido: --huella debe tener 64 caracteres hexadecimales")
        return RESULTADOS["formato_invalido"][1]
    documento = leer_documento(args.archivo)
    certificado = objeto_a_verificar(documento)
    estado = "formato_invalido" if documento is None else verificar(certificado, args.huella)
    resultado, codigo = RESULTADOS[estado]
    if estado == "sin_confianza_establecida":
        print(f"{resultado}: integridad verificada; emisor no verificado (falta --huella)")
    else:
        print(resultado)
    if certificado is not documento:
        print(AVISO_ENVOLTORIO)
    return codigo


if __name__ == "__main__":
    sys.exit(main())
