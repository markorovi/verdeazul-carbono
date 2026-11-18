"""Llaves del servicio de bitácora: la sal de seudonimización y la semilla de firma de los puntos.

Ambas son secretas y SOLO del servicio (en la nube, Secret Manager con acceso únicamente de su
cuenta de servicio). Se leen de variables de entorno, nunca se imprimen y los mensajes de error no
incluyen su valor. La llave de firma es distinta de la de certificados (CERT_SIGNING_KEY).
"""

from __future__ import annotations

import base64
import binascii
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VARIABLE_SAL = "BITACORA_SALT"
VARIABLE_FIRMA = "BITACORA_SIGNING_KEY"
BYTES_SEMILLA = 32
BYTES_SAL_MINIMO = 32
LARGO_KEY_ID = 16


class LlaveNoConfigurada(RuntimeError):
    """Falta una llave o es inválida. El mensaje nunca incluye el valor."""


def _base64(valor: str | None, variable: str) -> bytes:
    limpio = (valor or "").strip()
    if not limpio:
        raise LlaveNoConfigurada(f"Falta la variable de entorno {variable}.")
    try:
        return base64.b64decode(limpio, validate=True)
    except (binascii.Error, ValueError):
        raise LlaveNoConfigurada(f"{variable} no es base64 estándar válido.") from None


def cargar_sal(valor: str | None) -> bytes:
    sal = _base64(valor, VARIABLE_SAL)
    if len(sal) < BYTES_SAL_MINIMO:
        raise LlaveNoConfigurada(f"{VARIABLE_SAL} debe decodificar a {BYTES_SAL_MINIMO} bytes o más.")
    return sal


def cargar_llave(valor: str | None) -> Ed25519PrivateKey:
    semilla = _base64(valor, VARIABLE_FIRMA)
    if len(semilla) != BYTES_SEMILLA:
        raise LlaveNoConfigurada(f"{VARIABLE_FIRMA} debe decodificar a exactamente {BYTES_SEMILLA} bytes.")
    return Ed25519PrivateKey.from_private_bytes(semilla)


def clave_publica_cruda(llave: Ed25519PrivateKey) -> bytes:
    return llave.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def huella_publica(llave: Ed25519PrivateKey) -> str:
    return hashlib.sha256(clave_publica_cruda(llave)).hexdigest()


def key_id(llave: Ed25519PrivateKey) -> str:
    return huella_publica(llave)[:LARGO_KEY_ID]
