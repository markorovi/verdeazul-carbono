#!/usr/bin/env python3
"""Escáner de secretos del repositorio (solo biblioteca estándar).

Uso:
    python scripts/escanear_secretos.py            # árbol de trabajo y todo el historial
    python scripts/escanear_secretos.py --arbol    # solo el árbol de trabajo

Recorre el árbol de trabajo (archivos versionados y no ignorados) y todo el historial de git (todas
las ramas, etiquetas y referencias: git rev-list --all). Reglas:

- cadena_conexion: URL con usuario y contraseña (esquema://usuario:contraseña@host).
- clave_privada_pem: bloque PEM de clave privada.
- asignacion_secreta: literal largo y de alta entropía asignado a un nombre como password, secret,
  token, key, clave, salt o signing.

Imprime solo archivo, línea, commit y regla; NUNCA el valor encontrado. Termina con código 1 si hay
hallazgos, 2 si git falla y 0 si no hay ninguno.
"""

from __future__ import annotations

import argparse
import math
import re
import subprocess  # nosec B404
import sys
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
MAX_BYTES = 2 * 1024 * 1024
LARGO_MINIMO = 20
ENTROPIA_MINIMA = 3.8

_CONEXION = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://([^\s/:@'\"<>]+):([^\s@'\"<>/]+)@[^\s'\"<>]+")
_PEM = re.compile(r"-{5}BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-{5}")
_ASIGNACION = re.compile(
    r"(?P<nombre>[A-Za-z_$][\w.$:\[\]\"'-]{0,80}?)\s*(?::=|=|:)\s*[rbfu]?(?P<comilla>['\"])"
    r"(?P<valor>[^'\"\s]{%d,})(?P=comilla)" % LARGO_MINIMO
)
_PALABRAS = ("password", "passwd", "pwd", "contrasena", "contraseña", "secret", "secreto", "token",
             "apikey", "api_key", "key", "clave", "salt", "signing")
_MARCADORES = ("<", ">", "${", "{", "%(", "ficticio", "prueba", "ejemplo", "example", "changeme", "xxxx",
               "redactado", "dummy", "fake", "placeholder", "test", "local")
_CONTRASENAS_DE_EJEMPLO = {"contrasena", "contraseña", "password", "clave", "usuario", "pass", "secreto"}


def entropia(valor: str) -> float:
    conteo = Counter(valor)
    return -sum(n / len(valor) * math.log2(n / len(valor)) for n in conteo.values())


def _nombre_sensible(nombre: str) -> bool:
    bajo = nombre.lower()
    return any(p in bajo for p in _PALABRAS)


def analizar_texto(texto: str) -> list[tuple[int, str]]:
    """(línea, regla) de cada hallazgo. El valor nunca sale de esta función."""
    hallazgos = []
    for numero, linea in enumerate(texto.splitlines(), start=1):
        for coincidencia in _CONEXION.finditer(linea):
            contrasena = coincidencia.group(2)
            if contrasena.lower() not in _CONTRASENAS_DE_EJEMPLO and not any(m in contrasena.lower() for m in _MARCADORES):
                hallazgos.append((numero, "cadena_conexion"))
                break
        if _PEM.search(linea):
            hallazgos.append((numero, "clave_privada_pem"))
        for coincidencia in _ASIGNACION.finditer(linea):
            valor = coincidencia.group("valor")
            if (_nombre_sensible(coincidencia.group("nombre")) and "://" not in valor
                    and not any(m in valor.lower() for m in _MARCADORES) and entropia(valor) >= ENTROPIA_MINIMA):
                hallazgos.append((numero, "asignacion_secreta"))
                break
    return hallazgos


def _texto(datos: bytes) -> str | None:
    if len(datos) > MAX_BYTES or b"\0" in datos[:8192]:
        return None
    return datos.decode("utf-8", errors="replace")


def _git(*argumentos: str, entrada: bytes | None = None) -> bytes:
    # Bandit B603 aceptado: git con argumentos en lista y sin shell.
    resultado = subprocess.run(["git", *argumentos], cwd=RAIZ, input=entrada, capture_output=True,  # nosec B603 B607
                               check=False, timeout=600)
    if resultado.returncode != 0:
        raise RuntimeError(f"git {argumentos[0]} terminó con código {resultado.returncode}")
    return resultado.stdout


def escanear_arbol() -> list[tuple[str, int, str, str]]:
    hallazgos = []
    rutas = [r for r in _git("ls-files", "-z", "--cached", "--others", "--exclude-standard").decode("utf-8").split("\0") if r]
    for ruta in rutas:
        archivo = RAIZ / ruta
        if not archivo.is_file():
            continue
        texto = _texto(archivo.read_bytes())
        if texto is not None:
            hallazgos += [(ruta, linea, "arbol", regla) for linea, regla in analizar_texto(texto)]
    return hallazgos


def _leer_blobs(shas: list[str]) -> dict[str, bytes]:
    salida = _git("cat-file", "--batch", entrada="".join(f"{s}\n" for s in shas).encode("ascii"))
    contenidos, posicion = {}, 0
    while posicion < len(salida):
        fin = salida.index(b"\n", posicion)
        sha, _tipo, largo = salida[posicion:fin].decode("ascii").split(" ")
        inicio = fin + 1
        contenidos[sha] = salida[inicio:inicio + int(largo)]
        posicion = inicio + int(largo) + 1
    return contenidos


def escanear_historial() -> tuple[list[tuple[str, int, str, str]], int]:
    """Cada blob se analiza una vez, atribuido al primer commit (el más antiguo) que lo contiene."""
    commits = [c for c in _git("rev-list", "--all", "--reverse").decode("ascii").split() if c]
    primer_commit: dict[str, tuple[str, str]] = {}
    for commit in commits:
        for entrada in _git("ls-tree", "-r", "-z", commit).decode("utf-8").split("\0"):
            if not entrada:
                continue
            datos, ruta = entrada.split("\t", 1)
            _modo, tipo, sha = datos.split(" ")
            if tipo == "blob" and sha not in primer_commit:
                primer_commit[sha] = (ruta, commit)
    hallazgos = []
    shas = list(primer_commit)
    for i in range(0, len(shas), 500):
        for sha, datos in _leer_blobs(shas[i:i + 500]).items():
            texto = _texto(datos)
            if texto is None:
                continue
            ruta, commit = primer_commit[sha]
            hallazgos += [(ruta, linea, commit[:12], regla) for linea, regla in analizar_texto(texto)]
    return hallazgos, len(commits)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Busca secretos en el árbol y en el historial sin mostrarlos.")
    parser.add_argument("--arbol", action="store_true", help="solo el árbol de trabajo")
    args = parser.parse_args(argv)
    sys.stdout.reconfigure(errors="replace")
    try:
        hallazgos = escanear_arbol()
        commits = 0
        if not args.arbol:
            historial, commits = escanear_historial()
            hallazgos += historial
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"[FALLO] {error}")
        return 2
    for ruta, linea, commit, regla in sorted(set(hallazgos)):
        print(f"[FALLO] {ruta}:{linea} commit={commit} regla={regla}")
    alcance = "árbol de trabajo" if args.arbol else f"árbol de trabajo y {commits} commits de todas las referencias"
    if hallazgos:
        print(f"[FALLO] {len(set(hallazgos))} hallazgos en {alcance}.")
        return 1
    print(f"[OK] Sin hallazgos en {alcance}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
