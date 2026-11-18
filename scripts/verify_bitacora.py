#!/usr/bin/env python3
"""Verificador independiente de la bitácora de Verdeazul Carbono, para el auditor.

Solo usa la biblioteca estándar y cryptography; no importa nada del proyecto. Reproduce la fórmula
de BITACORA.md:

    hash_n = SHA-256( hash_{n-1} en hex ASCII || JSON canónico del evento n sin hash ni hash_previo )
    JSON canónico: claves ordenadas, separadores (",", ":"), ensure_ascii=False, UTF-8
    hash_0 = 64 ceros

Uso:
    python scripts/verify_bitacora.py --eventos bitacora.jsonl --puntos carpeta_puntos \\
        (--huella HEX64 | --clave-publica BASE64) [--cada 25]

Códigos de salida:
    0  íntegra
    1  cadena rota o secuencia con huecos
    2  firma de un punto inválida o clave no confiable
    3  un punto no coincide con la cadena (por ejemplo, la cadena se reescribió completa)
    4  formato inválido
    5  faltan puntos esperados (advertencia)

No imprime el contenido de los eventos.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

INTEGRA, CADENA, FIRMA, PUNTO, FORMATO, FALTAN = 0, 1, 2, 3, 4, 5
CEROS = "0" * 64
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NOMBRE_PUNTO = re.compile(r"^(\d{12})\.json$")


def canonico(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def calcular_hash(hash_previo: str, evento: dict) -> str:
    cuerpo = {k: v for k, v in evento.items() if k not in ("hash", "hash_previo")}
    return hashlib.sha256(hash_previo.encode("ascii") + canonico(cuerpo)).hexdigest()


def leer_eventos(ruta: Path) -> list[dict]:
    eventos = []
    with open(ruta, "rb") as archivo:
        for numero, linea in enumerate(archivo, start=1):
            if not linea.strip():
                continue
            evento = json.loads(linea.decode("utf-8"))
            if (not isinstance(evento, dict) or not isinstance(evento.get("seq"), int)
                    or not _HEX64.match(str(evento.get("hash", ""))) or not _HEX64.match(str(evento.get("hash_previo", "")))):
                raise ValueError(f"línea {numero} sin seq, hash o hash_previo válidos")
            eventos.append(evento)
    return eventos


def leer_puntos(carpeta: Path) -> dict[int, dict]:
    puntos = {}
    raiz = carpeta / "puntos" if (carpeta / "puntos").is_dir() else carpeta
    for ruta in sorted(raiz.glob("*.json")):
        coincidencia = _NOMBRE_PUNTO.match(ruta.name)
        if not coincidencia:
            raise ValueError("nombre de punto inesperado")
        documento = json.loads(ruta.read_bytes().decode("utf-8"))
        if not isinstance(documento, dict) or set(documento) != {"payload", "firma", "clave_publica"}:
            raise ValueError("documento de punto con formato inválido")
        if documento["payload"].get("seq") != int(coincidencia.group(1)):
            raise ValueError("el nombre del punto no coincide con su seq")
        puntos[int(coincidencia.group(1))] = documento
    return puntos


def huella_confiable(args) -> str:
    if args.huella:
        huella = args.huella.strip().lower()
        if not _HEX64.match(huella):
            raise ValueError("--huella debe ser SHA-256 en hexadecimal (64 caracteres)")
        return huella
    try:
        cruda = base64.b64decode(args.clave_publica.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("--clave-publica no es base64 válido") from None
    if len(cruda) != 32:
        raise ValueError("--clave-publica debe decodificar a 32 bytes")
    return hashlib.sha256(cruda).hexdigest()


def firma_valida(documento: dict, huella: str) -> bool:
    try:
        publica = base64.b64decode(documento["clave_publica"], validate=True)
        firma = base64.b64decode(documento["firma"], validate=True)
        if hashlib.sha256(publica).hexdigest() != huella or documento["payload"].get("key_id") != huella[:16]:
            return False
        Ed25519PublicKey.from_public_bytes(publica).verify(firma, canonico(documento["payload"]))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, binascii.Error):
        return False


def verificar(eventos: list[dict], puntos: dict[int, dict], huella: str, cada: int) -> tuple[int, str]:
    previo = CEROS
    hashes = {}
    for esperado, evento in enumerate(eventos, start=1):
        if evento["seq"] != esperado:
            return CADENA, f"secuencia con huecos o desordenada en la posición {esperado}"
        if evento["hash_previo"] != previo or calcular_hash(evento["hash_previo"], evento) != evento["hash"]:
            return CADENA, f"cadena rota en el evento {esperado}"
        hashes[esperado] = previo = evento["hash"]
    for seq, documento in sorted(puntos.items()):
        if not firma_valida(documento, huella):
            return FIRMA, f"el punto {seq} tiene una firma inválida o una clave no confiable"
    for seq, documento in sorted(puntos.items()):
        if hashes.get(seq) != documento["payload"].get("hash"):
            return PUNTO, f"el punto {seq} no coincide con la cadena"
    ultimo_multiplo = len(eventos) - len(eventos) % cada
    faltan = [s for s in range(cada, ultimo_multiplo + 1, cada) if s not in puntos]
    if faltan:
        return FALTAN, f"faltan {len(faltan)} puntos esperados (el primero, seq {faltan[0]})"
    return INTEGRA, f"{len(eventos)} eventos y {len(puntos)} puntos íntegros"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verifica la cadena y los puntos de control de la bitácora.")
    parser.add_argument("--eventos", required=True, help="exportación en JSON lines")
    parser.add_argument("--puntos", required=True, help="carpeta con los puntos descargados")
    confianza = parser.add_mutually_exclusive_group(required=True)
    confianza.add_argument("--huella", help="SHA-256 (64 hex) de la clave pública confiable")
    confianza.add_argument("--clave-publica", help="clave pública confiable en base64 (32 bytes)")
    parser.add_argument("--cada", type=int, default=25, help="cada cuántos eventos se espera un punto")
    args = parser.parse_args(argv)
    try:
        huella = huella_confiable(args)
        eventos = leer_eventos(Path(args.eventos))
        puntos = leer_puntos(Path(args.puntos))
        if args.cada < 1:
            raise ValueError("--cada debe ser positivo")
    except (OSError, ValueError, UnicodeDecodeError) as error:
        print(f"[FALLO] Formato inválido: {error}")
        return FORMATO
    codigo, detalle = verificar(eventos, puntos, huella, args.cada)
    etiqueta = {INTEGRA: "[OK]", FALTAN: "[AVISO]"}.get(codigo, "[FALLO]")
    print(f"{etiqueta} {detalle}")
    return codigo


if __name__ == "__main__":
    sys.exit(main())
