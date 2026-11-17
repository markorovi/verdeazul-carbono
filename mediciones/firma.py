"""Firma Ed25519 de certificados y su verificación.

La clave privada es una semilla de 32 bytes en base64 estándar en la variable CERT_SIGNING_KEY. Se
carga al primer uso (nunca al importar) y no aparece en mensajes de error ni en registros. La base
valida que el payload coincida con sus datos, pero no puede verificar la firma: eso ocurre aquí y en
scripts/verify_cert.py, que reimplementa la misma canonicalización sin depender del proyecto.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.core.exceptions import ImproperlyConfigured

from mediciones.huella import formatear_co2e

VARIABLE_CLAVE = "CERT_SIGNING_KEY"
ALG = "Ed25519"
BYTES_SEMILLA = 32
BYTES_CLAVE_PUBLICA = 32
BYTES_FIRMA = 64
LARGO_KEY_ID = 16
LARGO_SEUDONIMO = 16
# No existe en la base una fuente autoritativa de versión de política; la base solo exige que esté.
VERSION_POLITICA = "1"

CAMPOS_PAYLOAD = (
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
)
CAMPOS_DOCUMENTO = ("payload", "signature", "public_key", "alg")

ESTADO_VALIDO = "valido"
ESTADO_FIRMA_INVALIDA = "firma_invalida"
ESTADO_CLAVE_NO_CONFIABLE = "clave_no_confiable"
ESTADO_FORMATO_INVALIDO = "formato_invalido"
ESTADO_SIN_CONFIANZA = "sin_confianza_establecida"

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_CO2E = re.compile(r"^[0-9]+\.[0-9]{3}$")
_FECHA = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class ClaveDeFirmaNoConfigurada(ImproperlyConfigured):
    """CERT_SIGNING_KEY falta o es inválida. El mensaje nunca incluye el valor."""


@dataclass(frozen=True)
class Resultado:
    estado: str
    detalle: str


# --------------------------------------------------------------------------- claves


@lru_cache(maxsize=1)
def clave_privada() -> Ed25519PrivateKey:
    """Clave de firma de CERT_SIGNING_KEY. lru_cache no guarda los errores, solo la clave válida."""
    valor = os.environ.get(VARIABLE_CLAVE, "").strip()
    if not valor:
        raise ClaveDeFirmaNoConfigurada(f"Falta la variable de entorno {VARIABLE_CLAVE}.")
    try:
        semilla = base64.b64decode(valor, validate=True)
    except (binascii.Error, ValueError):
        raise ClaveDeFirmaNoConfigurada(f"{VARIABLE_CLAVE} no es base64 estándar válido.") from None
    if len(semilla) != BYTES_SEMILLA:
        raise ClaveDeFirmaNoConfigurada(f"{VARIABLE_CLAVE} debe decodificar a exactamente {BYTES_SEMILLA} bytes.")
    return Ed25519PrivateKey.from_private_bytes(semilla)


def _bytes_publicos(clave: Ed25519PrivateKey | None = None) -> bytes:
    return (clave or clave_privada()).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def clave_publica_b64(clave: Ed25519PrivateKey | None = None) -> str:
    return base64.b64encode(_bytes_publicos(clave)).decode("ascii")


def huella_publica(clave: Ed25519PrivateKey | None = None) -> str:
    """SHA-256 en hexadecimal (minúsculas) de los 32 bytes crudos de la clave pública."""
    return hashlib.sha256(_bytes_publicos(clave)).hexdigest()


def key_id(clave: Ed25519PrivateKey | None = None) -> str:
    return huella_publica(clave)[:LARGO_KEY_ID]


# --------------------------------------------------------------------------- payload


def canonico(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def seudonimo(usuario_id) -> str:
    """Seudónimo de un aprobador: SHA-256 del UUID en texto (minúsculas, con guiones), 16 hex."""
    return hashlib.sha256(str(usuario_id).lower().encode("utf-8")).hexdigest()[:LARGO_SEUDONIMO]


def formatear_fecha(momento: datetime) -> str:
    return momento.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def construir_payload(
    certificado_id,
    parcela_id,
    periodo_id,
    medicion_id,
    medicion_numero: int,
    co2e_toneladas,
    huella_medicion: str,
    aprobadores,
    fecha_emision: datetime,
    version_politica: str = VERSION_POLITICA,
    clave: Ed25519PrivateKey | None = None,
) -> dict:
    """Los 11 campos firmados. medicion_numero y huella_medicion son los de la versión aprobada."""
    return {
        "certificado_id": str(certificado_id),
        "parcela_id": str(parcela_id),
        "periodo_id": str(periodo_id),
        "medicion_id": str(medicion_id),
        "medicion_numero": int(medicion_numero),
        "co2e_toneladas": formatear_co2e(co2e_toneladas),
        "huella_medicion": huella_medicion,
        "aprobadores": sorted(seudonimo(a) for a in aprobadores),
        "fecha_emision": formatear_fecha(fecha_emision),
        "version_politica": version_politica,
        "key_id": key_id(clave),
    }


def firmar(payload: dict, clave: Ed25519PrivateKey | None = None) -> dict:
    privada = clave or clave_privada()
    firma = privada.sign(canonico(payload))
    return {
        "payload": payload,
        "signature": base64.b64encode(firma).decode("ascii"),
        "public_key": clave_publica_b64(privada),
        "alg": ALG,
    }


# --------------------------------------------------------------------------- verificación


def _b64(valor, largo: int) -> bytes | None:
    if not isinstance(valor, str):
        return None
    try:
        datos = base64.b64decode(valor, validate=True)
    except (binascii.Error, ValueError):
        return None
    return datos if len(datos) == largo else None


def _problema_de_payload(payload) -> str | None:
    if not isinstance(payload, dict):
        return "payload no es un objeto"
    if set(payload) != set(CAMPOS_PAYLOAD):
        return "payload no tiene exactamente los 11 campos esperados"
    for campo in ("certificado_id", "parcela_id", "periodo_id", "medicion_id"):
        if not isinstance(payload[campo], str) or not _UUID.match(payload[campo]):
            return f"{campo} no es un UUID"
    numero = payload["medicion_numero"]
    if isinstance(numero, bool) or not isinstance(numero, int) or numero < 1:
        return "medicion_numero no es un entero positivo"
    if not isinstance(payload["co2e_toneladas"], str) or not _CO2E.match(payload["co2e_toneladas"]):
        return "co2e_toneladas no tiene 3 decimales"
    if not isinstance(payload["huella_medicion"], str) or not _HEX64.match(payload["huella_medicion"]):
        return "huella_medicion no es SHA-256 hexadecimal"
    aprobadores = payload["aprobadores"]
    if not isinstance(aprobadores, list) or not all(isinstance(a, str) and _HEX16.match(a) for a in aprobadores):
        return "aprobadores no es una lista de seudónimos"
    if not isinstance(payload["fecha_emision"], str) or not _FECHA.match(payload["fecha_emision"]):
        return "fecha_emision no está en UTC ISO 8601 con sufijo Z"
    if not isinstance(payload["version_politica"], str) or not payload["version_politica"]:
        return "version_politica falta o está vacía"
    if not isinstance(payload["key_id"], str) or not _HEX16.match(payload["key_id"]):
        return "key_id no tiene 16 caracteres hexadecimales"
    return None


def verificar(documento, huella_confiable: str | None) -> Resultado:
    """Orden: formato, firma con la clave incrustada, confianza en la clave."""
    if not isinstance(documento, dict) or set(documento) != set(CAMPOS_DOCUMENTO):
        return Resultado(ESTADO_FORMATO_INVALIDO, "el documento no tiene exactamente payload, signature, public_key y alg")
    if documento["alg"] != ALG:
        return Resultado(ESTADO_FORMATO_INVALIDO, "alg no es Ed25519")
    problema = _problema_de_payload(documento["payload"])
    if problema:
        return Resultado(ESTADO_FORMATO_INVALIDO, problema)
    firma = _b64(documento["signature"], BYTES_FIRMA)
    if firma is None:
        return Resultado(ESTADO_FORMATO_INVALIDO, "signature no es base64 de 64 bytes")
    publica = _b64(documento["public_key"], BYTES_CLAVE_PUBLICA)
    if publica is None:
        return Resultado(ESTADO_FORMATO_INVALIDO, "public_key no es base64 de 32 bytes")
    try:
        clave_incrustada = Ed25519PublicKey.from_public_bytes(publica)
    except ValueError:
        return Resultado(ESTADO_FORMATO_INVALIDO, "public_key no es una clave Ed25519 válida")
    try:
        clave_incrustada.verify(firma, canonico(documento["payload"]))
    except InvalidSignature:
        return Resultado(ESTADO_FIRMA_INVALIDA, "la firma no corresponde al payload con la clave incrustada")
    huella = hashlib.sha256(publica).hexdigest()
    if huella_confiable is None:
        return Resultado(ESTADO_SIN_CONFIANZA, "firma coherente; no se indicó una huella confiable")
    if huella != huella_confiable.strip().lower():
        return Resultado(ESTADO_CLAVE_NO_CONFIABLE, "la firma es coherente pero la clave no es la confiable")
    return Resultado(ESTADO_VALIDO, "firma válida con la clave confiable")
