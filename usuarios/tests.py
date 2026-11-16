"""Pruebas de TOTP, cifrado y hasher que no necesitan base de datos."""

import base64
import os
import secrets
import uuid
from unittest import mock

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from usuarios import cifrado, totp

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
        self.assertTrue(hash_generado.startswith("argon2$argon2id$v=19$m=19456,t=2,p=1$"))
        self.assertTrue(check_password(contrasena, hash_generado))
        self.assertFalse(check_password(contrasena + "x", hash_generado))
