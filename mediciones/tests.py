"""Pruebas de huella, firma, plazos y errores de los servicios que no necesitan base de datos."""

import base64
import hashlib
import json
import os
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.db import IntegrityError
from django.test import SimpleTestCase

from mediciones import alertas, firma, plazos, servicios
from mediciones.errores import ParametroNoConfigurado, ReglaIncumplida
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

class DiasHabilesTests(SimpleTestCase):
    # 2026-11-16 es lunes.
    def test_casos(self):
        lunes = date(2026, 11, 16)
        casos = {
            lunes: 0,
            date(2026, 11, 17): 1,
            date(2026, 11, 20): 4,
            date(2026, 11, 21): 4,
            date(2026, 11, 22): 4,
            date(2026, 11, 23): 5,
            date(2026, 12, 7): 15,
            date(2026, 12, 8): 16,
        }
        for hasta, esperado in casos.items():
            with self.subTest(hasta=hasta):
                self.assertEqual(plazos.dias_habiles_entre(lunes, hasta), esperado)

    def test_desde_fin_de_semana_y_rango_invertido(self):
        self.assertEqual(plazos.dias_habiles_entre(date(2026, 11, 21), date(2026, 11, 23)), 1)
        self.assertEqual(plazos.dias_habiles_entre(date(2026, 11, 23), date(2026, 11, 16)), 0)

    def test_coincide_con_conteo_dia_a_dia(self):
        inicio = date(2026, 1, 1)
        for largo in range(0, 40):
            for desplazamiento in range(7):
                desde = inicio + timedelta(days=desplazamiento)
                hasta = desde + timedelta(days=largo)
                esperado = sum(
                    1 for d in range(1, largo + 1) if (desde + timedelta(days=d)).weekday() < 5
                )
                self.assertEqual(plazos.dias_habiles_entre(desde, hasta), esperado)

    def test_plazo_habil_vencido(self):
        cierre = datetime(2026, 11, 16, 18, 0, tzinfo=timezone.utc)
        self.assertFalse(plazos.plazo_habil_vencido(cierre, datetime(2026, 12, 7, 23, 0, tzinfo=timezone.utc), 15))
        self.assertTrue(plazos.plazo_habil_vencido(cierre, datetime(2026, 12, 8, 0, 1, tzinfo=timezone.utc), 15))


class PlazoEnmiendaTests(SimpleTestCase):
    cierre = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def test_dentro_y_fuera(self):
        self.assertTrue(plazos.enmienda_en_plazo(self.cierre, self.cierre + timedelta(days=89), 90, False))
        self.assertTrue(plazos.enmienda_en_plazo(self.cierre, self.cierre + timedelta(days=90), 90, False))
        self.assertFalse(plazos.enmienda_en_plazo(self.cierre, self.cierre + timedelta(days=90, seconds=1), 90, False))

    def test_certificado_anulado_sin_vigente(self):
        self.assertTrue(plazos.enmienda_en_plazo(self.cierre, self.cierre + timedelta(days=120), 90, True))

    def test_solicitud_fuera_de_plazo_con_vigente(self):
        self.assertFalse(plazos.enmienda_en_plazo(self.cierre, self.cierre + timedelta(days=120), 90, False))


class ParametrosTests(SimpleTestCase):
    def _con_valor(self, valor):
        consulta = mock.MagicMock()
        consulta.filter.return_value.values_list.return_value.first.return_value = valor
        return mock.patch.object(plazos.PoliticaParametro, "objects", consulta)

    def test_lee_el_valor(self):
        with self._con_valor(Decimal("500.000")):
            self.assertEqual(plazos.leer_parametro(plazos.CLAVE_VALTO), Decimal("500"))

    def test_falta_el_parametro(self):
        with self._con_valor(None):
            with self.assertRaises(ParametroNoConfigurado):
                plazos.leer_parametro(plazos.CLAVE_PLAZO_VERIFICACION)

    def test_entero(self):
        with self._con_valor(Decimal("90.000")):
            self.assertEqual(plazos.leer_parametro_entero(plazos.CLAVE_PLAZO_ENMIENDA), 90)
        for valor in (Decimal("1.500"), Decimal("0"), Decimal("-3")):
            with self.subTest(valor=valor), self._con_valor(valor):
                with self.assertRaises(ParametroNoConfigurado):
                    plazos.leer_parametro_entero(plazos.CLAVE_PLAZO_ENMIENDA)


class _ErrorDeBase(Exception):
    def __init__(self, sqlstate, mensaje="", restriccion=None):
        super().__init__(mensaje)
        self.sqlstate = sqlstate
        self.diag = mock.Mock(message_primary=mensaje, constraint_name=restriccion)


def _error_django(causa):
    error = IntegrityError("rechazo")
    error.__cause__ = causa
    return error


class ReglaDeLaBaseTests(SimpleTestCase):
    def test_atributos(self):
        regla = ReglaIncumplida("Cd7", "motivo")
        self.assertEqual((regla.condicion, regla.motivo), ("Cd7", "motivo"))

    def test_condicion_en_el_mensaje(self):
        casos = {
            "Aprobación rechazada (Cd8): quien registró...": "Cd8",
            "Certificado rechazado (H1, Cd10): la medición debe estar aprobada.": "Cd10",
        }
        for mensaje, condicion in casos.items():
            with self.subTest(condicion=condicion):
                regla = servicios._regla_de_la_base(_error_django(_ErrorDeBase("23000", mensaje)))
                self.assertEqual(regla.condicion, condicion)

    def test_restricciones_unicas(self):
        casos = {"certificado_vigente_unico": "Cd10", "aprobacion_unica_por_ciclo": "Cd8", "enmienda_una_solicitada": "Cd11"}
        for restriccion, condicion in casos.items():
            with self.subTest(restriccion=restriccion):
                regla = servicios._regla_de_la_base(_error_django(_ErrorDeBase("23505", "", restriccion)))
                self.assertEqual(regla.condicion, condicion)

    def test_sin_condicion_conocida(self):
        for causa in (_ErrorDeBase("23000", "Período rechazado: solo un actor R7."),
                      _ErrorDeBase("23505", "", "otra_restriccion"), _ErrorDeBase("42501", "permiso"), None):
            with self.subTest(causa=causa):
                self.assertIsNone(servicios._regla_de_la_base(_error_django(causa)))

class AlertasTests(SimpleTestCase):
    actor = uuid.UUID("33333333-3333-3333-3333-333333333333")
    cuenta = uuid.UUID("44444444-4444-4444-4444-444444444444")

    def _creada_por_el_actor(self, valor: bool):
        consulta = mock.MagicMock()
        consulta.filter.return_value.exists.return_value = valor
        return mock.patch.object(alertas.Usuario, "objects", consulta)

    def test_prioridad(self):
        with self._creada_por_el_actor(True):
            self.assertEqual(alertas.prioridad_para(self.actor, self.cuenta), alertas.PRIORITARIA)
        with self._creada_por_el_actor(False):
            self.assertEqual(alertas.prioridad_para(self.actor, self.cuenta), alertas.AVISO)

    def test_sin_cuenta_afectada_es_normal(self):
        with self._creada_por_el_actor(True):
            self.assertEqual(alertas.prioridad_para(self.actor, None), alertas.AVISO)

    def test_rechazos_de_la_base(self):
        casos = [
            _ErrorDeBase("23514", "", "alerta_resolucion_independiente"),
            _ErrorDeBase("23000", "Alerta: ya fue resuelta; no se vuelve a resolver."),
        ]
        for causa in casos:
            with self.subTest(causa=str(causa)):
                self.assertEqual(alertas._regla_de_la_base(_error_django(causa)).condicion, "Cd18")
        self.assertIsNone(alertas._regla_de_la_base(_error_django(_ErrorDeBase("23514", "", "otra"))))


class VerificadorIndependienteTests(SimpleTestCase):
    """scripts/verificar_certificado.py como lo usaría un tercero: proceso aparte, sin el proyecto en
    el camino de importación y con un certificado firmado en la prueba (nunca con la clave real)."""

    SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts",
                          "verificar_certificado.py")

    def setUp(self):
        import tempfile

        self.carpeta = tempfile.mkdtemp(prefix="verificador_")
        self.clave = Ed25519PrivateKey.generate()
        self.huella = firma.huella_publica(self.clave)
        payload = firma.construir_payload(
            uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 1, Decimal("100"), "a" * 64,
            [uuid.uuid4()], datetime(2026, 1, 15, tzinfo=timezone.utc), clave=self.clave,
        )
        self.documento = firma.firmar(payload, self.clave)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.carpeta, ignore_errors=True)

    def _correr(self, contenido: str, *extra) -> tuple[int, str]:
        import subprocess
        import sys

        ruta = os.path.join(self.carpeta, f"{uuid.uuid4().hex}.json")
        with open(ruta, "w", encoding="utf-8") as archivo:
            archivo.write(contenido)
        # -I: modo aislado; el proceso no ve el directorio del proyecto ni PYTHONPATH.
        proceso = subprocess.run([sys.executable, "-I", self.SCRIPT, ruta, *extra], capture_output=True,
                                 text=True, timeout=60, cwd=self.carpeta)
        return proceso.returncode, proceso.stdout.strip()

    def test_integro_y_emitido_por_la_clave_esperada(self):
        codigo, salida = self._correr(json.dumps(self.documento), "--huella", self.huella)
        self.assertEqual((codigo, salida), (0, "integro_emisor_esperado"))

    def test_integro_con_otra_clave(self):
        otra = firma.huella_publica(Ed25519PrivateKey.generate())
        codigo, salida = self._correr(json.dumps(self.documento), "--huella", otra)
        self.assertEqual((codigo, salida), (1, "integro_otra_clave"))

    def test_alterado(self):
        alterado = json.loads(json.dumps(self.documento))
        alterado["payload"]["co2e_toneladas"] = "100.001"
        codigo, salida = self._correr(json.dumps(alterado), "--huella", self.huella)
        self.assertEqual((codigo, salida), (2, "alterado"))

    def test_formato_invalido(self):
        self.assertEqual(self._correr("{no es json", "--huella", self.huella)[0], 3)
        self.assertEqual(self._correr(json.dumps({"payload": {}}), "--huella", self.huella)[0], 3)
        self.assertEqual(self._correr(json.dumps(self.documento), "--huella", "no-es-hex")[0], 3)

    def test_sin_huella_solo_integridad(self):
        codigo, salida = self._correr(json.dumps(self.documento))
        self.assertEqual(codigo, 4)
        self.assertTrue(salida.startswith("integro_sin_huella"))

    def test_archivo_exportado_completo(self):
        exportado = json.dumps(_envoltorio(self.documento))
        codigo, salida = self._correr(exportado, "--huella", self.huella)
        self.assertEqual((codigo, salida.splitlines()), (0, ["integro_emisor_esperado", AVISO_SCRIPT]))
        codigo, salida = self._correr(exportado)
        self.assertEqual(codigo, 4)
        self.assertEqual(salida.splitlines()[1:], [AVISO_SCRIPT])

    def test_archivo_exportado_alterado_o_mal_formado(self):
        alterado = _envoltorio(self.documento)
        alterado["certificado"]["payload"]["co2e_toneladas"] = "100.001"
        self.assertEqual(self._correr(json.dumps(alterado), "--huella", self.huella),
                         (2, f"alterado\n{AVISO_SCRIPT}"))
        extra = {**_envoltorio(self.documento), "nota": "x"}
        self.assertEqual(self._correr(json.dumps(extra), "--huella", self.huella), (3, "formato_invalido"))
        faltante = _envoltorio(self.documento)
        del faltante["trazabilidad"]
        self.assertEqual(self._correr(json.dumps(faltante), "--huella", self.huella), (3, "formato_invalido"))

    def test_objeto_interno_sin_aviso(self):
        self.assertEqual(self._correr(json.dumps(self.documento), "--huella", self.huella),
                         (0, "integro_emisor_esperado"))

    def test_no_importa_nada_del_proyecto(self):
        import ast

        with open(self.SCRIPT, encoding="utf-8") as archivo:
            arbol = ast.parse(archivo.read())
        modulos = {n.module.split(".")[0] for n in ast.walk(arbol) if isinstance(n, ast.ImportFrom) and n.module}
        modulos |= {a.name.split(".")[0] for n in ast.walk(arbol) if isinstance(n, ast.Import) for a in n.names}
        propios = {"mediciones", "usuarios", "catalogo", "autorizacion", "interfaz", "config", "bitacora_svc", "django"}
        self.assertFalse(modulos & propios)


AVISO_SCRIPT = "Se verifico el objeto certificado; estado y trazabilidad no estan firmados."


def _envoltorio(documento: dict) -> dict:
    """Misma forma que el archivo de la exportación O3.Ex (servicios.exportar_certificado)."""
    return {
        "certificado": json.loads(json.dumps(documento)),
        "estado": "vigente",
        "trazabilidad": [
            {"etapa": "registro", "rol": "R1", "fecha": "2026-01-10T12:00:00Z", "resultado": "registrada",
             "actor": "0" * 16},
            {"etapa": "emision", "rol": "R2", "fecha": "2026-01-15T00:00:00Z", "resultado": "emitido",
             "actor": "1" * 16},
        ],
    }


class EnvoltorioTests(SimpleTestCase):
    """firma.objeto_a_verificar: el archivo exportado completo se verifica por su objeto certificado."""

    def setUp(self):
        self.clave = Ed25519PrivateKey.generate()
        self.huella = firma.huella_publica(self.clave)
        payload = firma.construir_payload(
            uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 1, Decimal("100"), "a" * 64,
            [uuid.uuid4()], datetime(2026, 1, 15, tzinfo=timezone.utc), clave=self.clave,
        )
        self.documento = firma.firmar(payload, self.clave)

    def _estado(self, documento, huella=None) -> str:
        return firma.verificar(firma.objeto_a_verificar(documento), huella).estado

    def test_envoltorio_valido_y_emisor_coincide(self):
        envoltorio = _envoltorio(self.documento)
        self.assertEqual(firma.objeto_a_verificar(envoltorio), self.documento)
        self.assertEqual(self._estado(envoltorio, self.huella), firma.ESTADO_VALIDO)
        otra = firma.huella_publica(Ed25519PrivateKey.generate())
        self.assertEqual(self._estado(envoltorio, otra), firma.ESTADO_CLAVE_NO_CONFIABLE)

    def test_envoltorio_con_claves_de_mas_o_de_menos(self):
        extra = {**_envoltorio(self.documento), "nota": "x"}
        faltante = _envoltorio(self.documento)
        del faltante["estado"]
        sin_dict = {**_envoltorio(self.documento), "certificado": "texto"}
        for caso in (extra, faltante, sin_dict):
            with self.subTest(claves=sorted(caso)):
                self.assertIs(firma.objeto_a_verificar(caso), caso)
                self.assertEqual(self._estado(caso, self.huella), firma.ESTADO_FORMATO_INVALIDO)

    def test_certificado_interno_alterado(self):
        envoltorio = _envoltorio(self.documento)
        envoltorio["certificado"]["payload"]["co2e_toneladas"] = "100.001"
        self.assertEqual(self._estado(envoltorio, self.huella), firma.ESTADO_FIRMA_INVALIDA)

    def test_objeto_interno_igual_que_antes(self):
        self.assertIs(firma.objeto_a_verificar(self.documento), self.documento)
        self.assertEqual(self._estado(self.documento, self.huella), firma.ESTADO_VALIDO)
        for otro in (None, [], "texto", {"payload": {}}):
            self.assertIs(firma.objeto_a_verificar(otro), otro)

    def test_estado_y_trazabilidad_no_cambian_el_resultado(self):
        envoltorio = _envoltorio(self.documento)
        envoltorio["estado"] = "anulado"
        envoltorio["trazabilidad"] = [{"etapa": "inventada", "fecha": None}]
        self.assertEqual(self._estado(envoltorio, self.huella), firma.ESTADO_VALIDO)
        envoltorio["trazabilidad"] = "no es una lista"
        envoltorio["estado"] = None
        self.assertEqual(self._estado(envoltorio, self.huella), firma.ESTADO_VALIDO)

    def test_el_script_desenvuelve_igual(self):
        import importlib.util

        ruta = VerificadorIndependienteTests.SCRIPT
        especificacion = importlib.util.spec_from_file_location("verificar_certificado_paridad", ruta)
        script = importlib.util.module_from_spec(especificacion)
        especificacion.loader.exec_module(script)
        self.assertEqual(set(script.CAMPOS_ENVOLTORIO), set(firma.CAMPOS_ENVOLTORIO))
        envoltorio = _envoltorio(self.documento)
        casos = [envoltorio, self.documento, {**envoltorio, "nota": 1}, {**envoltorio, "certificado": []},
                 {"certificado": {}, "estado": None}, None, [], "texto"]
        for caso in casos:
            with self.subTest(caso=type(caso).__name__):
                propio, ajeno = firma.objeto_a_verificar(caso), script.objeto_a_verificar(caso)
                self.assertIs(propio, ajeno)
                self.assertEqual(firma.verificar(propio, self.huella).estado, script.verificar(ajeno, self.huella))
