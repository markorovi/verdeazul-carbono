"""Pruebas de TOTP, cifrado, hasher, códigos de un solo uso y ventanas que no necesitan base de datos."""

import base64
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from unittest import mock

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import CommandError
from django.test import SimpleTestCase

from usuarios import cifrado, codigos, totp, ventanas
from usuarios.autenticacion import _hash_ficticio
from usuarios.management.commands.crear_cuentas_prueba import (
    DOMINIO_POR_DEFECTO,
    cuentas_para,
    validar_dominio,
)

PREFIJO_ARGON2ID = "argon2$argon2id$v=19$m=19456,t=2,p=1$"

SECRETO_RFC = base64.b32encode(b"12345678901234567890").decode("ascii")
VECTORES_RFC_SHA1 = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


def clave_falsa() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


class TotpTests(SimpleTestCase):
    def test_vectores_rfc_6238_sha1(self):
        for instante, esperado in VECTORES_RFC_SHA1:
            with self.subTest(instante=instante):
                self.assertEqual(totp.codigo_para(SECRETO_RFC, instante, digitos=8), esperado)

    def test_ventana_acepta_un_paso_a_cada_lado(self):
        instante = 1_700_000_000
        actual = totp.paso_de(instante)
        for desfase in (-1, 0, 1):
            with self.subTest(desfase=desfase):
                codigo = totp.codigo_para(SECRETO_RFC, instante + desfase * totp.PASO_SEGUNDOS)
                self.assertEqual(totp.verificar(SECRETO_RFC, codigo, instante), actual + desfase)

    def test_ventana_rechaza_dos_pasos(self):
        instante = 1_700_000_000
        for desfase in (-2, 2):
            with self.subTest(desfase=desfase):
                codigo = totp.codigo_para(SECRETO_RFC, instante + desfase * totp.PASO_SEGUNDOS)
                self.assertIsNone(totp.verificar(SECRETO_RFC, codigo, instante))

    def test_rechaza_formatos_invalidos(self):
        secreto = totp.generar_secreto()
        for codigo in ("", "12345", "1234567", "abcdef", "12345٣"):
            with self.subTest(codigo=codigo):
                self.assertIsNone(totp.verificar(secreto, codigo, 1_700_000_000))

    def test_secreto_generado(self):
        secreto = totp.generar_secreto()
        self.assertEqual(len(secreto), 32)
        self.assertNotIn("=", secreto)
        self.assertNotEqual(secreto, totp.generar_secreto())


class CifradoTests(SimpleTestCase):
    def setUp(self):
        self.secreto = totp.generar_secreto()
        self.usuario = uuid.uuid4()

    def test_ida_y_vuelta(self):
        with mock.patch.dict(os.environ, {"CLAVE_TOTP": clave_falsa()}):
            blob = cifrado.cifrar(self.secreto, self.usuario)
            self.assertNotIn(self.secreto.encode("ascii"), blob)
            self.assertEqual(cifrado.descifrar(blob, self.usuario), self.secreto)

    def test_otra_clave_falla(self):
        with mock.patch.dict(os.environ, {"CLAVE_TOTP": clave_falsa()}):
            blob = cifrado.cifrar(self.secreto, self.usuario)
        with mock.patch.dict(os.environ, {"CLAVE_TOTP": clave_falsa()}):
            with self.assertRaises(cifrado.SecretoIlegible):
                cifrado.descifrar(blob, self.usuario)

    def test_otro_usuario_falla(self):
        with mock.patch.dict(os.environ, {"CLAVE_TOTP": clave_falsa()}):
            blob = cifrado.cifrar(self.secreto, self.usuario)
            with self.assertRaises(cifrado.SecretoIlegible):
                cifrado.descifrar(blob, uuid.uuid4())

    def test_byte_alterado_falla(self):
        with mock.patch.dict(os.environ, {"CLAVE_TOTP": clave_falsa()}):
            blob = bytearray(cifrado.cifrar(self.secreto, self.usuario))
            blob[-1] ^= 0x01
            with self.assertRaises(cifrado.SecretoIlegible):
                cifrado.descifrar(bytes(blob), self.usuario)

    def test_clave_ausente_o_invalida(self):
        corta = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii")
        for valor in ("", "no es base64 valido", corta):
            with self.subTest(largo=len(valor)):
                with mock.patch.dict(os.environ, {"CLAVE_TOTP": valor}):
                    with self.assertRaises(ImproperlyConfigured) as contexto:
                        cifrado.cifrar(self.secreto, self.usuario)
                    if valor:
                        self.assertNotIn(valor, str(contexto.exception))


class HasherTests(SimpleTestCase):
    def test_un_unico_hasher_propio(self):
        self.assertEqual(settings.PASSWORD_HASHERS, ["usuarios.hashers.Argon2idHasher"])

    def test_formato_y_verificacion(self):
        contrasena = secrets.token_urlsafe(16)
        hash_generado = make_password(contrasena)
        self.assertTrue(hash_generado.startswith(PREFIJO_ARGON2ID))
        self.assertTrue(check_password(contrasena, hash_generado))
        self.assertFalse(check_password(contrasena + "x", hash_generado))

    def test_hash_ficticio_calculado_al_arrancar(self):
        self.assertEqual(_hash_ficticio.cache_info().currsize, 1)
        self.assertTrue(_hash_ficticio().startswith(PREFIJO_ARGON2ID))


class DominioCuentasPruebaTests(SimpleTestCase):
    def test_dominios_validos(self):
        for dominio in (DOMINIO_POR_DEFECTO, "autoprueba.test", "a-b.c1.test"):
            with self.subTest(dominio=dominio):
                self.assertEqual(validar_dominio(dominio), dominio)

    def test_dominios_invalidos(self):
        for dominio in ("", "Verdeazul.test", "a@b.test", "con espacio.test", "sinpunto", "-a.test", "a..test"):
            with self.subTest(dominio=dominio):
                with self.assertRaises(CommandError):
                    validar_dominio(dominio)

    def test_correos_con_el_dominio(self):
        cuentas = cuentas_para("autoprueba.test")
        self.assertEqual(len(cuentas), 7)
        self.assertEqual([rol for _, rol in cuentas], ["R1", "R2", "R3", "R4", "R5", "R6", "R7"])
        self.assertTrue(all(correo.endswith("@autoprueba.test") for correo, _ in cuentas))

def _utc(anio, mes, dia, hora=0):
    return datetime(anio, mes, dia, hora, tzinfo=timezone.utc)


class VentanasTests(SimpleTestCase):
    def test_dentro_de_un_anio(self):
        self.assertEqual(ventanas.segundos_por_anio(_utc(2099, 1, 1), _utc(2099, 1, 21)), {2099: 20 * 86400})

    def test_cruza_el_cambio_de_anio(self):
        partes = ventanas.segundos_por_anio(_utc(2098, 12, 29), _utc(2099, 1, 3, 12))
        self.assertEqual(partes, {2098: 3 * 86400, 2099: int(2.5 * 86400)})

    def test_limite(self):
        existentes = [(_utc(2099, 1, 1), _utc(2099, 1, 21))]
        self.assertFalse(ventanas.excede_limite(existentes, (_utc(2099, 2, 1), _utc(2099, 2, 11)), 30))
        self.assertTrue(ventanas.excede_limite(existentes, (_utc(2099, 2, 1), _utc(2099, 2, 11, 1)), 30))

    def test_el_limite_es_por_anio(self):
        existentes = [(_utc(2098, 6, 1), _utc(2098, 6, 30))]
        self.assertFalse(ventanas.excede_limite(existentes, (_utc(2099, 1, 1), _utc(2099, 1, 30)), 30))
        cruza = (_utc(2098, 12, 30), _utc(2099, 1, 2))
        self.assertTrue(ventanas.excede_limite(existentes, cruza, 30))


class CodigosTests(SimpleTestCase):
    ahora = _utc(2099, 1, 1, 12)

    def test_generar_es_de_256_bits_y_unico(self):
        codigo = codigos.generar()
        relleno = "=" * (-len(codigo) % 4)
        self.assertEqual(len(base64.urlsafe_b64decode(codigo + relleno)), 32)
        self.assertNotEqual(codigo, codigos.generar())

    def test_huella_y_comparacion(self):
        codigo = codigos.generar()
        huella = codigos.huella(codigo)
        self.assertEqual(len(huella), 64)
        self.assertNotIn(codigo, huella)
        self.assertTrue(codigos.coincide(huella, codigo))
        self.assertFalse(codigos.coincide(huella, codigos.generar()))

    def test_vigencias(self):
        self.assertEqual(codigos.vigencia("alta"), timedelta(hours=24))
        self.assertEqual(codigos.vigencia("recuperacion"), timedelta(minutes=30))

    def test_disponible(self):
        vence = self.ahora + timedelta(minutes=1)
        self.assertTrue(codigos.disponible(vence, None, 0, self.ahora))
        self.assertTrue(codigos.disponible(vence, None, 4, self.ahora))
        self.assertFalse(codigos.disponible(vence, None, 5, self.ahora))
        self.assertFalse(codigos.disponible(vence, self.ahora, 0, self.ahora))
        self.assertFalse(codigos.disponible(self.ahora, None, 0, self.ahora))
