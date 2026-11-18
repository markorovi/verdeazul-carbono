#!/usr/bin/env python3
"""Pruebas del comando sembrar_demo contra la base dev, siempre en una transacción revertida.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_demo.py

Ninguna cuenta de demostración queda confirmada en dev: cada prueba corre en una transacción que se
revierte y al final se comparan los conteos. La bitácora es un servicio real sobre un esquema
temporal (como en probar_bitacora.py). Los archivos de credenciales van a una carpeta temporal fuera
del repositorio y se borran; las contraseñas y los secretos TOTP nunca se imprimen.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

if os.environ.get("ENTORNO") != "local" or "VERDEAZUL_PROD" in os.environ:
    raise SystemExit("[FALLO] Solo corre con ENTORNO=local y sin VERDEAZUL_PROD.")

import probar_bitacora as pb  # noqa: E402  (configura Django, app_rw y la bitácora de prueba)

from django.contrib.auth.hashers import check_password  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.core.management.base import CommandError  # noqa: E402
from django.test import override_settings  # noqa: E402

import probar_autorizacion as pa  # noqa: E402
import probar_mediciones as pm  # noqa: E402
import probar_servicios as ps  # noqa: E402
from bitacora_svc import esquema  # noqa: E402
from catalogo.models import Asignacion, Finca, Parcela, Propiedad  # noqa: E402
from mediciones.models import Periodo  # noqa: E402
from usuarios import cifrado  # noqa: E402
from usuarios.hashers import Argon2idHasher  # noqa: E402
from usuarios.management.commands import sembrar_demo  # noqa: E402
from usuarios.models import ExclusionEstatica, RolUsuario, Usuario  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
INSTANCIA: pb.Instancia | None = None
CARPETA: Path | None = None


def ruta_nueva() -> Path:
    return CARPETA / f"credenciales_demo_{uuid.uuid4().hex[:8]}.json"


def sembrar(ruta: Path, *opciones) -> tuple[str, str]:
    salida, errores = io.StringIO(), io.StringIO()
    call_command("sembrar_demo", "--salida", str(ruta), *opciones, stdout=salida, stderr=errores)
    return salida.getvalue(), errores.getvalue()


def leer(ruta: Path) -> list[dict]:
    return json.loads(ruta.read_text(encoding="utf-8"))["cuentas"]


def sin_credenciales(texto: str, credenciales: list[dict]) -> bool:
    return not any(c["contrasena"] in texto or c["secreto_totp"] in texto for c in credenciales)


def demo() -> dict[str, Usuario]:
    return {rol: Usuario.objects.get(correo=correo) for rol, correo in sembrar_demo.correos().items()}


def d01():
    ruta = ruta_nueva()
    salida, errores = sembrar(ruta)
    credenciales = leer(ruta)
    cuentas = demo()
    roles = {rol: sorted(RolUsuario.objects.filter(usuario=u, hasta__isnull=True).values_list("rol_id", flat=True))
             for rol, u in cuentas.items()}
    campos = all(set(c) == {"rol", "usuario", "contrasena", "secreto_totp", "uri_otpauth"} for c in credenciales)
    un_rol = len(credenciales) == 7 and all(roles[r] == [r] for r in roles)
    uris = all(c["uri_otpauth"].startswith("otpauth://totp/") for c in credenciales)
    fuera = not str(ruta.resolve()).lower().startswith(str(RAIZ.resolve()).lower())
    limpia = sin_credenciales(salida + errores, credenciales) and str(ruta.resolve()) in salida
    ok = un_rol and campos and uris and fuera and limpia
    return ok, (f"7 cuentas con un rol={un_rol}; campos y URI={campos and uris}; fuera del repo={fuera};"
                f" consola solo con conteos y ruta={limpia}")


def d02():
    ruta = ruta_nueva()
    sembrar(ruta)
    credenciales = {c["rol"]: c for c in leer(ruta)}
    cuentas = demo()
    argon = all(u.password.startswith(f"{Argon2idHasher.algorithm}$argon2id$") for u in cuentas.values())
    claves = all(check_password(credenciales[r]["contrasena"], u.password) for r, u in cuentas.items())
    largo = all(len(c["contrasena"]) >= 20 for c in credenciales.values())
    totp = all(cifrado.descifrar(u.totp_secreto_cifrado, u.pk) == credenciales[r]["secreto_totp"]
               for r, u in cuentas.items())
    return argon and claves and largo and totp, f"Argon2id={argon}; contraseñas válidas={claves}; 20+ caracteres={largo}; TOTP coincide={totp}"


def d03():
    sembrar(ruta_nueva())
    cuentas = demo()
    pares = set(ExclusionEstatica.objects.values_list("rol_a_id", "rol_b_id"))
    violadas = 0
    for u in cuentas.values():
        vigentes = set(RolUsuario.objects.filter(usuario=u, hasta__isnull=True).values_list("rol_id", flat=True))
        violadas += sum(1 for a, b in pares if a in vigentes and b in vigentes)
    return violadas == 0 and len(pares) > 0, f"pares excluyentes={len(pares)}; violados={violadas}"


def d04():
    sembrar(ruta_nueva())
    cuentas = demo()
    finca = Finca.objects.get(nombre=sembrar_demo.FINCA, propiedades__dueno=cuentas["R6"])
    parcelas = list(Parcela.objects.filter(finca=finca).values_list("pk", flat=True))
    propietario = Propiedad.objects.filter(finca=finca, dueno=cuentas["R6"], hasta__isnull=True).exists()
    asignada = Asignacion.objects.filter(tecnico=cuentas["R1"], parcela_id__in=parcelas).count()
    d = ps.Datos()
    d.actor(cuentas["R7"])
    abiertos = Periodo.objects.filter(estado="abierto").count()
    ok = len(parcelas) == 3 and propietario and asignada == 1 and abiertos >= 1
    return ok, f"parcelas={len(parcelas)}; dueño R6={propietario}; asignaciones R1={asignada}; períodos abiertos={abiertos}"


def d05():
    sembrar(ruta_nueva())
    antes = Usuario.objects.count()
    segunda = ruta_nueva()
    salida, _ = sembrar(segunda)
    ok = "ya existen" in salida and Usuario.objects.count() == antes and not segunda.exists()
    return ok, f"segunda ejecución sin cambios={Usuario.objects.count() == antes}; sin archivo nuevo={not segunda.exists()}"


def d06():
    primera = ruta_nueva()
    sembrar(primera)
    viejas = {c["rol"]: c for c in leer(primera)}
    rotada = ruta_nueva()
    salida, errores = sembrar(rotada, "--rotar")
    nuevas = {c["rol"]: c for c in leer(rotada)}
    cuentas = demo()
    cambiadas = all(not check_password(viejas[r]["contrasena"], u.password) and check_password(nuevas[r]["contrasena"], u.password)
                    for r, u in cuentas.items())
    totp = all(cifrado.descifrar(u.totp_secreto_cifrado, u.pk) == nuevas[r]["secreto_totp"] != viejas[r]["secreto_totp"]
               for r, u in cuentas.items())
    ok = cambiadas and totp and sin_credenciales(salida + errores, list(nuevas.values()))
    return ok, f"contraseñas rotadas={cambiadas}; secretos TOTP rotados={totp}"


def d07():
    antes = Usuario.objects.count()
    dentro = RAIZ / f"credenciales_demo_{uuid.uuid4().hex[:8]}.json"
    try:
        sembrar(dentro)
        rechazo = False
    except CommandError:
        rechazo = True
    existente = ruta_nueva()
    existente.write_text("{}", encoding="utf-8")
    try:
        sembrar(existente)
        pisado = True
    except CommandError:
        pisado = False
    ok = rechazo and not dentro.exists() and not pisado and Usuario.objects.count() == antes
    return ok, f"ruta dentro del repo rechazada={rechazo}; archivo existente sin pisar={not pisado}; sin cuentas={Usuario.objects.count() == antes}"


def d08():
    antes = Usuario.objects.count()
    ruta = ruta_nueva()
    with override_settings(BITACORA_URL=f"http://127.0.0.1:{pa.puerto_libre()}"):
        try:
            sembrar(ruta)
            abortado = False
        except CommandError:
            abortado = True
    ok = abortado and Usuario.objects.count() == antes and not ruta.exists()
    return ok, f"sin bitácora aborta={abortado}; sin cuentas ni archivo={Usuario.objects.count() == antes and not ruta.exists()}"


def d09():
    sembrar(ruta_nueva())
    r4 = demo()["R4"]
    eventos = INSTANCIA.cliente.consultar(usuario_id=str(r4.pk), limite=20, orden="desc")
    arranque = [e for e in eventos if e.get("operacion") == "O6.Al" and e.get("origen") == "sistema"
                and e.get("motivo") == "arranque_cuenta_administradora_demo"]
    return len(arranque) == 1, f"eventos de arranque del primer R4 en la bitácora={len(arranque)}"


def con_motivo(funcion):
    """Un CommandError inesperado se informa con su mensaje: son textos fijos del comando, sin credenciales."""
    def prueba():
        try:
            return funcion()
        except CommandError as error:
            return False, f"CommandError: {str(error)[:120]}"
    return prueba


PRUEBAS = [
    ("D01", "7 cuentas, un rol cada una; archivo fuera del repositorio; nada impreso", "7; sin credenciales", d01),
    ("D02", "Contraseñas Argon2id de 20+ caracteres y secretos TOTP del mecanismo existente", "argon2id; coinciden", d02),
    ("D03", "Exclusiones entre roles respetadas", "0 violadas", d03),
    ("D04", "Finca, 3 parcelas, dueño R6, técnico R1 asignado y período abierto", "3; 1; abierto", d04),
    ("D05", "Idempotente: con las cuentas creadas no hace nada", "sin cambios", d05),
    ("D06", "--rotar regenera contraseñas y secretos TOTP", "rotados", d06),
    ("D07", "Rechaza una ruta dentro del repositorio y no pisa un archivo", "rechazos", d07),
    ("D08", "Sin bitácora no crea nada", "aborta", d08),
    ("D09", "El arranque del primer R4 queda en la bitácora", "1 evento", d09),
]


def main() -> int:
    global INSTANCIA, CARPETA
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    pb.logging.getLogger("verdeazul").setLevel(pb.logging.ERROR)
    nombre = f"{esquema.PREFIJO_PRUEBA}{uuid.uuid4().hex[:10]}"
    CARPETA = Path(tempfile.mkdtemp(prefix="demo_"))
    try:
        INSTANCIA = pb.Instancia(nombre)
        ps.usar(ps.APP)
        iniciales = pa.conteos()
        with override_settings(BITACORA_URL=INSTANCIA.url):
            resultados = [ps.ejecutar(i, d, e, con_motivo(f)) for i, d, e, f in PRUEBAS]
        finales = pa.conteos()
    finally:
        if INSTANCIA is not None:
            INSTANCIA.cerrar()
        ps.connections["default"].close()
        shutil.rmtree(CARPETA, ignore_errors=True)
    restantes = pb.esquemas_restantes([nombre])
    pm.imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    print(f"\nTotal: {correctas}/{len(resultados)} OK")
    print(f"Esquemas temporales restantes: {restantes}; archivos temporales borrados: {not CARPETA.exists()}")
    limpio = finales == iniciales
    print(f"Conteos antes: {iniciales}")
    print(f"Conteos después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio and restantes == 0 else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio and restantes == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
