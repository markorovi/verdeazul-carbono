"""Cuentas y datos mínimos de demostración para recorrer en vivo el flujo medición -> certificado.

    python manage.py sembrar_demo --salida <ruta fuera del repositorio>
    python manage.py sembrar_demo --salida <ruta> --rotar

Crea 7 cuentas (una por rol, R1 a R7; ningún par excluyente) y, con los servicios existentes: una
finca con su dueño R6, 3 parcelas sin traslape en la misma finca (la región del técnico, Cd22), el
técnico R1 asignado a la primera parcela y un período abierto.

Arranque: el alta de cuentas exige un actor R4 y todavía no hay ninguno, así que la primera cuenta
R4 se crea directamente (como crear_cuentas_prueba) y ese arranque queda registrado en la bitácora;
si la bitácora no lo confirma, no se crea nada. Las demás cuentas pasan por alta_cuenta, el canje del
código de alta (contraseña y secreto TOTP del mecanismo existente) y asignar_rol, como R4.

Las contraseñas son aleatorias (20 caracteres o más, Argon2id) y van, con el secreto TOTP en base32
y la URI otpauth, solo al archivo de --salida, que debe quedar fuera del repositorio y no existir.
La consola muestra solo conteos y la ruta. Es idempotente: si las 7 cuentas ya existen no hace nada;
--rotar regenera las contraseñas y los secretos TOTP de esas cuentas (no toca CLAVE_TOTP).
"""

from __future__ import annotations

import json
import os
from datetime import date, timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from autorizacion.bitacora import bitacora_configurada
from catalogo import servicios as catalogo
from mediciones import servicios as mediciones
from mediciones.transaccion import hora_de_la_base
from usuarios import cifrado, totp
from usuarios import servicios as cuentas
from usuarios.management.commands.crear_cuentas_prueba import generar_contrasena
from usuarios.models import RolUsuario, Usuario

DOMINIO = "demo.verdeazul.test"
CUENTAS = [
    ("R1", "demo.r1.tecnico", "Técnico de demostración"),
    ("R2", "demo.r2.verificador", "Verificador de demostración"),
    ("R3", "demo.r3.catalogo", "Catálogo de demostración"),
    ("R4", "demo.r4.cuentas", "Administración de cuentas de demostración"),
    ("R5", "demo.r5.auditor", "Auditor de demostración"),
    ("R6", "demo.r6.dueno", "Dueño de demostración"),
    ("R7", "demo.r7.certificacion", "Certificación de demostración"),
]
FINCA = "Finca de demostración"
# Tres cuadrados de 100 m en CRTM05 (SRID 5367), separados 50 m: sin traslape entre sí.
X0, Y0, LADO, SEPARACION = 480000, 1100000, 100, 50
CODIGOS_PARCELA = ("DEMO-1", "DEMO-2", "DEMO-3")
DIAS_ASIGNACION = 365
SERVICIO = "sembrar_demo"


def correos() -> dict[str, str]:
    return {rol: f"{local}@{DOMINIO}" for rol, local, _ in CUENTAS}


def cuadrado(indice: int) -> str:
    x = X0 + indice * (LADO + SEPARACION)
    return f"POLYGON(({x} {Y0}, {x + LADO} {Y0}, {x + LADO} {Y0 + LADO}, {x} {Y0 + LADO}, {x} {Y0}))"


def validar_salida(valor: str) -> Path:
    """Fuera del repositorio, en una carpeta que existe y sin pisar un archivo."""
    ruta = Path(valor).expanduser().resolve()
    repositorio = Path(settings.BASE_DIR).resolve()
    normal = os.path.normcase(str(ruta))
    raiz = os.path.normcase(str(repositorio))
    if normal == raiz or normal.startswith(raiz + os.sep):
        raise CommandError("La ruta de --salida queda dentro del repositorio; use una ruta fuera de él.")
    if not ruta.parent.is_dir():
        raise CommandError("La carpeta de --salida no existe.")
    if ruta.exists():
        raise CommandError("El archivo de --salida ya existe; no se sobrescribe.")
    return ruta


def escribir(ruta: Path, credenciales: list[dict]) -> None:
    contenido = json.dumps({
        "advertencia": "Credenciales de demostración. No las versione ni las comparta por chat.",
        "cuentas": credenciales,
    }, ensure_ascii=False, indent=2).encode("utf-8")
    descriptor = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as archivo:
        archivo.write(contenido)


def _credencial(rol: str, correo: str, contrasena: str, secreto: str) -> dict:
    return {"rol": rol, "usuario": correo, "contrasena": contrasena, "secreto_totp": secreto,
            "uri_otpauth": totp.uri_aprovisionamiento(correo, secreto)}


def _registrar(evento: dict) -> None:
    """La bitácora debe confirmar el evento; si no, se aborta todo (la transacción se revierte)."""
    try:
        bitacora_configurada().registrar({"origen": "sistema", "servicio": SERVICIO, **evento})
    except Exception as error:
        raise CommandError(f"La bitácora no confirmó el evento ({type(error).__name__}); no se hizo ningún cambio.") from None


class Command(BaseCommand):
    help = "Crea las cuentas y los datos mínimos de demostración; las credenciales van solo al archivo de --salida."

    def add_arguments(self, parser):
        parser.add_argument("--salida", required=True, help="Archivo de credenciales, fuera del repositorio.")
        parser.add_argument("--rotar", action="store_true",
                            help="Regenera contraseñas y secretos TOTP de las cuentas de demostración.")

    def handle(self, *args, **opciones):
        ruta = validar_salida(opciones["salida"])
        existentes = Usuario.objects.filter(correo__in=correos().values()).count()
        if opciones["rotar"]:
            if existentes != len(CUENTAS):
                raise CommandError("--rotar exige que existan las 7 cuentas de demostración.")
            with transaction.atomic():
                credenciales = self._rotar()
                escribir(ruta, credenciales)
            self.stdout.write(f"Cuentas de demostración rotadas: {len(credenciales)}. Credenciales en: {ruta}")
            return
        if existentes == len(CUENTAS):
            self.stdout.write("Las 7 cuentas de demostración ya existen; no se hizo ningún cambio.")
            return
        if existentes:
            raise CommandError(f"Hay {existentes} de 7 cuentas de demostración: estado parcial; revíselo antes de sembrar.")
        with transaction.atomic():
            credenciales, conteos = self._sembrar()
            escribir(ruta, credenciales)
        resumen = ", ".join(f"{clave}: {valor}" for clave, valor in conteos.items())
        self.stdout.write(f"Demostración sembrada ({resumen}). Credenciales en: {ruta}")

    # ----------------------------------------------------------------------- siembra

    def _arranque_r4(self, correo: str, nombre: str) -> tuple[Usuario, dict]:
        """Primera cuenta R4: no hay otro R4 que la dé de alta (alta_cuenta exige actor)."""
        usuario = Usuario(correo=correo, nombre=nombre, creado_en=hora_de_la_base())
        contrasena = generar_contrasena(usuario)
        secreto = totp.generar_secreto()
        usuario.password = make_password(contrasena)
        usuario.totp_secreto_cifrado = cifrado.cifrar(secreto, usuario.pk)
        usuario.save(force_insert=True)
        RolUsuario.objects.create(usuario=usuario, rol_id="R4")
        _registrar({"accion": "resultado", "resultado": "exito", "operacion": "O6.Al", "objeto_tipo": "cuenta",
                    "objeto_id": str(usuario.pk), "usuario_id": str(usuario.pk), "rol_activo": "R4",
                    "motivo": "arranque_cuenta_administradora_demo"})
        return usuario, _credencial("R4", correo, contrasena, secreto)

    def _sembrar(self) -> tuple[list[dict], dict]:
        direcciones = correos()
        nombres = {rol: nombre for rol, _, nombre in CUENTAS}
        r4, credencial_r4 = self._arranque_r4(direcciones["R4"], nombres["R4"])
        usuarios, credenciales = {"R4": r4}, {"R4": credencial_r4}
        for rol, _, nombre in CUENTAS:
            if rol == "R4":
                continue
            alta = cuentas.alta_cuenta(r4, direcciones[rol], nombre)
            cuenta = Usuario.objects.get(pk=alta.usuario_id)
            contrasena = generar_contrasena(cuenta)
            canje = cuentas.canjear_codigo(alta.codigo, correo=direcciones[rol], contrasena=contrasena)
            cuentas.asignar_rol(r4, alta.usuario_id, rol)
            usuarios[rol] = Usuario.objects.get(pk=alta.usuario_id)
            credenciales[rol] = _credencial(rol, direcciones[rol], contrasena, canje.secreto_totp)
        finca = catalogo.crear_finca(usuarios["R3"], FINCA, [usuarios["R6"].pk]).finca_id
        parcelas = [catalogo.crear_parcela(usuarios["R3"], finca, codigo, cuadrado(i)).parcela_id
                    for i, codigo in enumerate(CODIGOS_PARCELA)]
        catalogo.asignar_tecnico(usuarios["R3"], parcelas[0], usuarios["R1"].pk,
                                 hora_de_la_base() + timedelta(days=DIAS_ASIGNACION))
        hoy = date.today()
        mediciones.abrir_periodo(usuarios["R7"], date(hoy.year, 1, 1), date(hoy.year, 12, 31))
        conteos = {"cuentas": len(usuarios), "fincas": 1, "parcelas": len(parcelas), "asignaciones": 1, "períodos": 1}
        return [credenciales[rol] for rol, _, _ in CUENTAS], conteos

    def _rotar(self) -> list[dict]:
        ahora = hora_de_la_base()
        credenciales = []
        for rol, _, _ in CUENTAS:
            cuenta = Usuario.objects.get(correo=correos()[rol])
            contrasena = generar_contrasena(cuenta)
            secreto = totp.generar_secreto()
            Usuario.objects.filter(pk=cuenta.pk).update(
                password=make_password(contrasena), totp_secreto_cifrado=cifrado.cifrar(secreto, cuenta.pk),
                totp_confirmado=False, totp_ultimo_paso=None, intentos_fallidos=0, bloqueado_hasta=None,
            )
            cuentas._cerrar_sesiones(cuenta.pk, ahora)
            _registrar({"accion": "resultado", "resultado": "exito", "operacion": "O6.Md", "objeto_tipo": "cuenta",
                        "objeto_id": str(cuenta.pk), "motivo": "rotacion_credenciales_demostracion"})
            credenciales.append(_credencial(rol, cuenta.correo, contrasena, secreto))
        return credenciales
