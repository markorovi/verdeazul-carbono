"""TOTP según RFC 6238 (HMAC-SHA1, 6 dígitos, paso de 30 s) con la biblioteca estándar."""

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote, urlencode

PASO_SEGUNDOS = 30
DIGITOS = 6
BYTES_SECRETO = 20
EMISOR = "Verdeazul Carbono"


def generar_secreto() -> str:
    """Secreto aleatorio de 20 bytes en base32, sin relleno."""
    return base64.b32encode(secrets.token_bytes(BYTES_SECRETO)).decode("ascii").rstrip("=")


def _bytes_del_secreto(secreto_base32: str) -> bytes:
    limpio = secreto_base32.replace(" ", "").upper()
    return base64.b32decode(limpio + "=" * (-len(limpio) % 8))


def paso_de(instante: float) -> int:
    return int(instante // PASO_SEGUNDOS)


def _codigo_del_paso(clave: bytes, paso: int, digitos: int) -> str:
    mac = hmac.new(clave, struct.pack(">Q", paso), hashlib.sha1).digest()
    desplazamiento = mac[-1] & 0x0F
    binario = struct.unpack(">I", mac[desplazamiento:desplazamiento + 4])[0] & 0x7FFFFFFF
    return str(binario % 10**digitos).zfill(digitos)


def codigo_para(secreto_base32: str, instante: float, digitos: int = DIGITOS) -> str:
    """Código TOTP para el instante dado (segundos desde la época Unix)."""
    return _codigo_del_paso(_bytes_del_secreto(secreto_base32), paso_de(instante), digitos)


def verificar(secreto_base32: str, codigo: str, instante: float, ventana: int = 1) -> int | None:
    """Devuelve el paso en el que el código es válido (tolerando `ventana` pasos) o None."""
    if not isinstance(codigo, str) or len(codigo) != DIGITOS or not (codigo.isascii() and codigo.isdigit()):
        return None
    clave = _bytes_del_secreto(secreto_base32)
    actual = paso_de(instante)
    valido = None
    # Se recorren todos los pasos de la ventana para no cortar antes según cuál coincida.
    for paso in range(max(0, actual - ventana), actual + ventana + 1):
        if hmac.compare_digest(_codigo_del_paso(clave, paso, DIGITOS), codigo) and valido is None:
            valido = paso
    return valido


def uri_aprovisionamiento(correo: str, secreto: str, emisor: str = EMISOR) -> str:
    """URI otpauth para registrar la cuenta en una aplicación autenticadora."""
    etiqueta = quote(f"{emisor}:{correo}", safe="@:")
    parametros = urlencode(
        {
            "secret": secreto,
            "issuer": emisor,
            "algorithm": "SHA1",
            "digits": DIGITOS,
            "period": PASO_SEGUNDOS,
        },
        quote_via=quote,
    )
    return f"otpauth://totp/{etiqueta}?{parametros}"
