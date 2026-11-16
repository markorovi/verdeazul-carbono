"""Pruebas de la huella de versiones que no necesitan base de datos."""

import uuid
from datetime import date
from decimal import Decimal

from django.test import SimpleTestCase

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
