"""Cifrado del secreto TOTP con AES-256-GCM.

Formato del blob: nonce de 12 bytes seguido del texto cifrado con su etiqueta. El id del usuario
va como datos asociados, así que un blob copiado a otra cuenta no descifra.
"""

import base64
import binascii
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.core.exceptions import ImproperlyConfigured

VARIABLE_CLAVE = "CLAVE_TOTP"
BYTES_CLAVE = 32
BYTES_NONCE = 12


class SecretoIlegible(Exception):
    """El blob no se pudo descifrar (clave, usuario o contenido distintos)."""


def _clave() -> bytes:
    """Lee la clave en cada uso; los mensajes de error nunca incluyen su valor."""
    valor = os.environ.get(VARIABLE_CLAVE, "").strip()
    if not valor:
        raise ImproperlyConfigured(f"Falta la variable de entorno {VARIABLE_CLAVE}.")
    try:
        clave = base64.b64decode(valor + "=" * (-len(valor) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise ImproperlyConfigured(f"{VARIABLE_CLAVE} no es base64url válido.") from None
    if len(clave) != BYTES_CLAVE:
        raise ImproperlyConfigured(f"{VARIABLE_CLAVE} debe decodificar a exactamente {BYTES_CLAVE} bytes.")
    return clave


def _datos_asociados(id_usuario) -> bytes:
    return str(id_usuario).encode("ascii")


def cifrar(secreto_base32: str, id_usuario) -> bytes:
    nonce = secrets.token_bytes(BYTES_NONCE)
    cifrado = AESGCM(_clave()).encrypt(
        nonce, secreto_base32.encode("ascii"), _datos_asociados(id_usuario)
    )
    return nonce + cifrado


def descifrar(blob, id_usuario) -> str:
    datos = bytes(blob)
    nonce, cifrado = datos[:BYTES_NONCE], datos[BYTES_NONCE:]
    try:
        claro = AESGCM(_clave()).decrypt(nonce, cifrado, _datos_asociados(id_usuario))
    except (InvalidTag, ValueError):
        raise SecretoIlegible("No se pudo descifrar el secreto TOTP.") from None
    return claro.decode("ascii")
