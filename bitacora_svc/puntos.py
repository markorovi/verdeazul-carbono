"""Puntos de control firmados: (n, hn, fecha) firmados con Ed25519 por la llave de la bitácora.

Documento de un punto (JSON canónico, el mismo formato que lee scripts/verify_bitacora.py):
    {"payload": {"version": 1, "seq": n, "hash": hn, "fecha": "...Z", "alg": "Ed25519", "key_id": ...},
     "firma": base64(Ed25519(canonico(payload))), "clave_publica": base64(clave pública cruda)}
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from bitacora_svc import claves
from bitacora_svc.contrato import canonico

VERSION = 1
ALG = "Ed25519"


def documento(llave: Ed25519PrivateKey, seq: int, hash_evento: str, fecha: str) -> dict:
    payload = {
        "version": VERSION,
        "seq": seq,
        "hash": hash_evento,
        "fecha": fecha,
        "alg": ALG,
        "key_id": claves.key_id(llave),
    }
    return {
        "payload": payload,
        "firma": base64.b64encode(llave.sign(canonico(payload))).decode("ascii"),
        "clave_publica": base64.b64encode(claves.clave_publica_cruda(llave)).decode("ascii"),
    }


def leer(contenido: bytes) -> dict:
    datos = json.loads(contenido.decode("utf-8"))
    if not isinstance(datos, dict) or set(datos) != {"payload", "firma", "clave_publica"}:
        raise ValueError("documento de punto con formato inválido")
    return datos


def firma_valida(doc: dict, huella_confiable: str) -> bool:
    """Firma correcta y clave igual a la confiable (por huella SHA-256 de la clave cruda)."""
    try:
        publica = base64.b64decode(doc["clave_publica"], validate=True)
        firma = base64.b64decode(doc["firma"], validate=True)
        if hashlib.sha256(publica).hexdigest() != huella_confiable:
            return False
        if doc["payload"].get("key_id") != huella_confiable[: claves.LARGO_KEY_ID]:
            return False
        Ed25519PublicKey.from_public_bytes(publica).verify(firma, canonico(doc["payload"]))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return False
