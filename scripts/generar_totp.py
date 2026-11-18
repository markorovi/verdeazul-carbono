#!/usr/bin/env python3
"""Código TOTP vigente para entrar sin una aplicación autenticadora (solo biblioteca estándar).

Uso:
    python scripts/generar_totp.py

Pide el secreto en base32 con entrada oculta (no queda en el historial de la terminal ni se muestra)
y muestra el código de 6 dígitos vigente y los segundos que le quedan. Mismo algoritmo que la
aplicación: RFC 6238, HMAC-SHA1, 6 dígitos, paso de 30 s.
"""

from __future__ import annotations

import base64
import binascii
import getpass
import hashlib
import hmac
import struct
import sys
import time

PASO_SEGUNDOS = 30
DIGITOS = 6


def clave(secreto_base32: str) -> bytes:
    limpio = secreto_base32.replace(" ", "").strip().upper()
    if not limpio:
        raise ValueError("secreto vacío")
    return base64.b32decode(limpio + "=" * (-len(limpio) % 8))


def codigo(secreto_base32: str, instante: float) -> str:
    mac = hmac.new(clave(secreto_base32), struct.pack(">Q", int(instante // PASO_SEGUNDOS)), hashlib.sha1).digest()
    desplazamiento = mac[-1] & 0x0F
    binario = struct.unpack(">I", mac[desplazamiento:desplazamiento + 4])[0] & 0x7FFFFFFF
    return str(binario % 10**DIGITOS).zfill(DIGITOS)


def main() -> int:
    try:
        secreto = getpass.getpass("Secreto TOTP (base32, no se muestra): ")
    except (EOFError, KeyboardInterrupt):
        return 1
    ahora = time.time()
    try:
        valor = codigo(secreto, ahora)
    except (ValueError, binascii.Error):
        print("El secreto no es base32 válido.")
        return 1
    restante = PASO_SEGUNDOS - int(ahora % PASO_SEGUNDOS)
    print(f"Código vigente: {valor} (vence en {restante} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
