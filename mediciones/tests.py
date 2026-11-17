"""Pruebas de la huella de versiones y de la firma de certificados que no necesitan base de datos."""

import base64
import hashlib
import json
import os
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.test import SimpleTestCase

from mediciones import firma
from mediciones.huella import calcular_huella, formatear_co2e

ENTRADA = {
    "medicion_id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
    "numero": 1,
    "co2e_toneladas": Decimal("123.4"),
    "fecha_muestreo": date(2026, 1, 15),
    "notas": "Muestreo de prueba",
    "creada_por_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
    "huella_previa": None,
}
# SHA-256 de "1111...|1|123.400|2026-01-15|Muestreo de prueba|2222...|".
HUELLA_REFERENCIA = "c0a635e77dbf2aa4786302d1ba7adeed36be10406647806b3b06a1a7660c25c2"


class HuellaTests(SimpleTestCase):
    def test_vector_de_referencia(self):
        self.assertEqual(calcular_huella(**ENTRADA), HUELLA_REFERENCIA)

    def test_cambia_con_cada_campo(self):
        variantes = {
            "medicion_id": uuid.UUID("33333333-3333-3333-3333-333333333333"),
            "numero": 2,
            "co2e_toneladas": Decimal("123.401"),
            "fecha_muestreo": date(2026, 1, 16),
            "notas": "Otra nota",
            "creada_por_id": uuid.UUID("44444444-4444-4444-4444-444444444444"),
            "huella_previa": "a" * 64,
        }
        for campo, valor in variantes.items():
            with self.subTest(campo=campo):
                self.assertNotEqual(calcular_huella(**{**ENTRADA, campo: valor}), HUELLA_REFERENCIA)

    def test_notas_nulas_y_vacias_son_iguales(self):
        self.assertEqual(
            calcular_huella(**{**ENTRADA, "notas": None}), calcular_huella(**{**ENTRADA, "notas": ""})
        )

    def test_co2e_con_tres_decimales(self):
        casos = {
            Decimal("500"): "500.000",
            Decimal("123.4"): "123.400",
            Decimal("0.0005"): "0.001",
            "12.3456": "12.346",
            1: "1.000",
        }
        for valor, esperado in casos.items():
            with self.subTest(valor=valor):
                self.assertEqual(formatear_co2e(valor), esperado)


def _payload(clave):
    return firma.construir_payload(
        uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 2, Decimal("123.4"), "b" * 64,
        [uuid.UUID("22222222-2222-2222-2222-222222222222"), uuid.UUID("11111111-1111-1111-1111-111111111111")],
        datetime(2026, 11, 17, 15, 30, 5, 123456, tzinfo=timezone.utc), clave=clave,
    )


class CanonicoTests(SimpleTestCase):
    def test_orden_separadores_y_utf8(self):
        self.assertEqual(firma.canonico({"b": 1, "a": "ñ", "c": [2, 1]}), '{"a":"ñ","b":1,"c":[2,1]}'.encode("utf-8"))

    def test_independiente_del_orden_de_entrada(self):
        self.assertEqual(firma.canonico({"x": 1, "y": {"b": 2, "a": 1}}), firma.canonico({"y": {"a": 1, "b": 2}, "x": 1}))


class FirmaTests(SimpleTestCase):
    def setUp(self):
        self.clave = Ed25519PrivateKey.generate()
        self.documento = firma.firmar(_payload(self.clave), self.clave)
        self.huella = firma.huella_publica(self.clave)

    def test_payload_con_los_11_campos(self):
        payload = self.documento["payload"]
        self.assertEqual(set(payload), set(firma.CAMPOS_PAYLOAD))
        self.assertEqual(payload["co2e_toneladas"], "123.400")
        self.assertEqual(payload["fecha_emision"], "2026-11-17T15:30:05Z")
        self.assertEqual(payload["key_id"], self.huella[:16])
        seudonimos = [hashlib.sha256(u.encode("utf-8")).hexdigest()[:16] for u in
                      ("11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")]
        self.assertEqual(payload["aprobadores"], sorted(seudonimos))

    def test_documento(self):
        self.assertEqual(self.documento["alg"], "Ed25519")
        self.assertEqual(len(base64.b64decode(self.documento["signature"])), 64)
        self.assertEqual(len(base64.b64decode(self.documento["public_key"])), 32)
        self.assertEqual(hashlib.sha256(base64.b64decode(self.documento["public_key"])).hexdigest(), self.huella)

    def test_valido(self):
        self.assertEqual(firma.verificar(self.documento, self.huella).estado, firma.ESTADO_VALIDO)

    def test_payload_alterado(self):
        alterado = json.loads(json.dumps(self.documento))
        alterado["payload"]["medicion_numero"] = 3
        self.assertEqual(firma.verificar(alterado, self.huella).estado, firma.ESTADO_FIRMA_INVALIDA)

    def test_clave_ajena(self):
        ajena = Ed25519PrivateKey.generate()
        documento = firma.firmar(_payload(ajena), ajena)
        self.assertEqual(firma.verificar(documento, self.huella).estado, firma.ESTADO_CLAVE_NO_CONFIABLE)

    def test_sin_huella_confiable(self):
        self.assertEqual(firma.verificar(self.documento, None).estado, firma.ESTADO_SIN_CONFIANZA)

    def test_formato_invalido(self):
        variantes = []
        for campo in ("payload", "signature", "public_key", "alg"):
            sin_campo = dict(self.documento)
            del sin_campo[campo]
            variantes.append(sin_campo)
        variantes.append({**self.documento, "alg": "RS256"})
        variantes.append({**self.documento, "signature": "%%%"})
        variantes.append({**self.documento, "public_key": base64.b64encode(b"x" * 31).decode("ascii")})
        variantes.append("no es un objeto")
        for variante in variantes:
            with self.subTest(variante=type(variante).__name__):
                self.assertEqual(firma.verificar(variante, self.huella).estado, firma.ESTADO_FORMATO_INVALIDO)


class ClaveDeFirmaTests(SimpleTestCase):
    def tearDown(self):
        firma.clave_privada.cache_clear()

    def _con_valor(self, valor):
        firma.clave_privada.cache_clear()
        return mock.patch.dict(os.environ, {firma.VARIABLE_CLAVE: valor})

    def test_carga_valida_con_salto_de_linea(self):
        semilla = base64.b64encode(os.urandom(32)).decode("ascii")
        with self._con_valor(semilla + "\n"):
            self.assertEqual(len(firma.key_id()), 16)

    def test_errores_sin_el_valor(self):
        for valor in ("", base64.b64encode(os.urandom(16)).decode("ascii"), "no-es-base64!!"):
            with self.subTest(largo=len(valor)):
                with self._con_valor(valor):
                    with self.assertRaises(firma.ClaveDeFirmaNoConfigurada) as contexto:
                        firma.huella_publica()
                    if valor:
                        self.assertNotIn(valor, str(contexto.exception))
