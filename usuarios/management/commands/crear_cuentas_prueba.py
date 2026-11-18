"""Crea una cuenta de prueba por rol (R1 a R7) y muestra sus credenciales una sola vez."""

import re
import secrets
import string
import uuid

from django.contrib.auth.hashers import make_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from usuarios import cifrado, totp
from usuarios.models import RolUsuario, Usuario

DOMINIO_POR_DEFECTO = "verdeazul.test"
CUENTAS = [
    ("r1.tecnico", "R1"),
    ("r2.verificador", "R2"),
    ("r3.catalogo", "R3"),
    ("r4.cuentas", "R4"),
    ("r5.auditor", "R5"),
    ("r6.dueno", "R6"),
    ("r7.certificacion", "R7"),
]
# Etiquetas de letras minúsculas, números y guiones (sin guion al inicio ni al final), separadas por puntos.
PATRON_DOMINIO = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
LONGITUD_CONTRASENA = 20
ALFABETO = string.ascii_letters + string.digits + "-_.!@#%+="
INTENTOS_GENERACION = 50


def generar_contrasena(usuario: Usuario) -> str:
    """Contraseña aleatoria que pasa los validadores configurados."""
    for _ in range(INTENTOS_GENERACION):
        candidata = "".join(secrets.choice(ALFABETO) for _ in range(LONGITUD_CONTRASENA))
        try:
            validate_password(candidata, user=usuario)
        except ValidationError:
            continue
        return candidata
    raise RuntimeError("No se pudo generar una contraseña que cumpla la política.")


def validar_dominio(dominio: str) -> str:
    if len(dominio) > 253 or not PATRON_DOMINIO.fullmatch(dominio):
        raise CommandError(
            "Dominio inválido: use solo letras minúsculas, números, guiones y puntos"
            " (por ejemplo verdeazul.test), sin arroba ni espacios."
        )
    return dominio


def cuentas_para(dominio: str) -> list[tuple[str, str]]:
    """Pares (correo, rol) de las 7 cuentas de prueba con el dominio dado."""
    return [(f"{local}@{dominio}", rol) for local, rol in CUENTAS]


class Command(BaseCommand):
    help = "Crea las 7 cuentas de prueba (una por rol) y muestra sus credenciales una sola vez."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dominio",
            default=DOMINIO_POR_DEFECTO,
            help=f"Dominio de los correos (por defecto {DOMINIO_POR_DEFECTO}).",
        )

    def handle(self, *args, **options):
        dominio = validar_dominio(options["dominio"])
        creadas = []
        with transaction.atomic():
            for correo, rol in cuentas_para(dominio):
                if Usuario.objects.filter(correo=correo).exists():
                    self.stdout.write(f"{correo}: ya existe; no se modifica.")
                    continue
                creadas.append(self._crear(correo, rol))
        if creadas:
            self._imprimir(creadas)
        else:
            self.stdout.write("No se creó ninguna cuenta.")

    def _crear(self, correo: str, rol: str) -> tuple[str, str, str, str]:
        usuario_id = uuid.uuid4()
        nombre = f"Cuenta de prueba {rol}"
        contrasena = generar_contrasena(Usuario(correo=correo, nombre=nombre))
        secreto = totp.generar_secreto()
        usuario = Usuario.objects.create(
            id=usuario_id,
            correo=correo,
            nombre=nombre,
            password=make_password(contrasena),
            totp_secreto_cifrado=cifrado.cifrar(secreto, usuario_id),
        )
        RolUsuario.objects.create(usuario=usuario, rol_id=rol)
        return correo, rol, contrasena, secreto

    def _imprimir(self, creadas) -> None:
        self.stdout.write(
            "ADVERTENCIA: estas credenciales se muestran una sola vez. Guárdelas en un gestor de"
            " contraseñas; nunca en el repositorio ni en chats."
        )
        self.stdout.write("correo | rol | contraseña | secreto TOTP | URI de aprovisionamiento")
        for correo, rol, contrasena, secreto in creadas:
            uri = totp.uri_aprovisionamiento(correo, secreto)
            self.stdout.write(f"{correo} | {rol} | {contrasena} | {secreto} | {uri}")
