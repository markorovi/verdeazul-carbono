"""Pruebas de las utilidades de los servicios de catálogo que no necesitan base de datos."""

import uuid
from unittest import mock

from django.db import IntegrityError, InternalError
from django.test import SimpleTestCase

from catalogo import servicios

A = uuid.UUID("11111111-1111-1111-1111-111111111111")
B = uuid.UUID("22222222-2222-2222-2222-222222222222")


class _ErrorDeBase(Exception):
    def __init__(self, sqlstate, mensaje="", restriccion=None):
        super().__init__(mensaje)
        self.sqlstate = sqlstate
        self.diag = mock.Mock(message_primary=mensaje, constraint_name=restriccion)


def _error(causa, clase=IntegrityError):
    error = clase("rechazo")
    error.__cause__ = causa
    return error


class IdentificadoresTests(SimpleTestCase):
    def test_normaliza_y_quita_repetidos_en_orden(self):
        self.assertEqual(servicios._ids([str(B), A, str(A).upper(), B]), [B, A])

    def test_vacio(self):
        self.assertEqual(servicios._ids(None), [])
        self.assertEqual(servicios._ids(()), [])

    def test_valor_invalido(self):
        with self.assertRaises(ValueError):
            servicios._ids(["no-es-un-uuid"])


class ReglaDeLaBaseTests(SimpleTestCase):
    def test_traslape(self):
        regla = servicios._regla_de_la_base(_error(_ErrorDeBase("23000", "Traslape de parcelas: el polígono ...")))
        self.assertEqual(regla.condicion, "UNIDAD")

    def test_asignacion_sin_r1(self):
        regla = servicios._regla_de_la_base(_error(_ErrorDeBase("23000", "Asignación rechazada: el usuario ...")))
        self.assertEqual(regla.condicion, "Cd14")

    def test_restricciones(self):
        casos = {
            ("23505", "parcela_codigo_unico_por_finca"): "CODIGO",
            ("23514", "parcela_geom_valida"): "GEOMETRIA",
            ("23505", "propiedad_vigente_unica"): "PROPIEDAD",
            ("23514", "asignacion_hasta_posterior"): "Cd14",
        }
        for (sqlstate, restriccion), condicion in casos.items():
            with self.subTest(restriccion=restriccion):
                regla = servicios._regla_de_la_base(_error(_ErrorDeBase(sqlstate, "", restriccion)))
                self.assertEqual(regla.condicion, condicion)

    def test_wkt_mal_formado(self):
        causa = _ErrorDeBase("XX000", "parse error - invalid geometry")
        self.assertEqual(servicios._regla_de_la_base(_error(causa, InternalError)).condicion, "GEOMETRIA")

    def test_sin_condicion_conocida(self):
        for causa in (_ErrorDeBase("42501", "permiso"), _ErrorDeBase("23505", "", "otra"), None):
            with self.subTest(causa=causa):
                self.assertIsNone(servicios._regla_de_la_base(_error(causa)))

    def test_el_motivo_no_incluye_datos_de_la_base(self):
        mensaje = "Traslape de parcelas: el polígono se superpone con la parcela 1234"
        regla = servicios._regla_de_la_base(_error(_ErrorDeBase("23000", mensaje)))
        self.assertNotIn("1234", regla.motivo)
