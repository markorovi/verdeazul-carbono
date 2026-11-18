"""Pruebas de la capa de autorización que no necesitan base de datos."""

import inspect
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase, override_settings

from autorizacion import motor, pdp, pep, pip
from autorizacion.bitacora import BitacoraEnMemoria, bitacora_configurada
from usuarios import autenticacion

PARAMETROS = {
    "h2_wc_laboral_blando": 10,
    "h2_wc_laboral_duro": 25,
    "h2_wc_fuera_blando": 3,
    "h2_wc_fuera_duro": 8,
    "h2_wl_blando": 40,
    "h2_wl_duro": 100,
}
TODOS = {
    "asignacion_vigente": True,
    "propietario": True,
    "ventana_vigente": True,
    "segundo_factor": True,
    "proyeccion_disponible": True,
    "bitacora_disponible": True,
    "estado_visible_r2": True,
    "misma_region": True,
    "h2": {"disponible": True, "ajena": False, "wc": 0, "wl": 0, "laboral": True},
}
DENEGADAS_A_TODOS = {"O1.MdC", "O1.El", "O2.Ro", "O3.El", "O4.El", "O5.El", "O7.Es", "O7.MdE", "O8.Cf"}


def entrada(operacion, roles, cambios=None, emergencia=None):
    return {
        "sujeto": {"id": "0123456789abcdef", "roles": list(roles), "emergencia": emergencia},
        "operacion": operacion,
        "hechos": {**TODOS, **(cambios or {})},
        "parametros": PARAMETROS,
    }


def violar(condicion):
    if condicion == "Cd9":
        return {"h2": {"disponible": True, "ajena": True, "wc": 100, "wl": 100, "laboral": True}}
    return {motor.HECHOS[condicion]: False}


class MatrizTests(SimpleTestCase):
    def setUp(self):
        self.m = motor.matriz()
        self.ops = self.m["operaciones"]
        self.permisos = [(op, rol, conds) for op, porrol in self.ops.items() for rol, conds in porrol.items()]

    def test_cifras(self):
        self.assertEqual(len(self.ops), 41)
        self.assertEqual(len(self.m["objetos"]), 8)
        self.assertEqual(len(self.m["roles"]), 7)
        self.assertEqual(len(self.m["objetos"]) * len(self.m["roles"]), 56)
        self.assertEqual(len(self.permisos), 60)
        self.assertEqual(sum(1 for _, _, c in self.permisos if c), 53)
        self.assertEqual(sum(1 for _, _, c in self.permisos if not c), 7)
        distintas = {c for _, _, conds in self.permisos for c in conds}
        self.assertEqual(len(distintas), 24)
        denegadas = {op for op, porrol in self.ops.items() if not porrol}
        self.assertEqual(denegadas, DENEGADAS_A_TODOS)
        self.assertEqual(len(self.ops) - len(denegadas), 32)

    def test_celdas_con_permiso(self):
        celdas = {(motor.objeto_de(op), rol) for op, rol, _ in self.permisos}
        self.assertEqual(len(celdas), 33)

    def test_capas_de_condiciones(self):
        politica = set(self.m["condiciones_politica"])
        servicio = set(self.m["condiciones_servicio"])
        self.assertEqual(len(politica), 9)
        self.assertEqual(len(servicio), 15)
        self.assertFalse(politica & servicio)
        usadas = {c for _, _, conds in self.permisos for c in conds}
        self.assertEqual(usadas, politica | servicio)
        self.assertEqual(set(motor.HECHOS) | {"Cd9"}, politica)

    def test_objetos_y_roles_validos(self):
        for op, rol, _ in self.permisos:
            self.assertIn(motor.objeto_de(op), self.m["objetos"])
            self.assertIn(rol, self.m["roles"])


class MotorTests(SimpleTestCase):
    def test_celda_por_celda(self):
        for op, porrol in motor.matriz()["operaciones"].items():
            for rol in motor.matriz()["roles"]:
                with self.subTest(op=op, rol=rol):
                    d = motor.decidir(entrada(op, [rol]))
                    self.assertEqual(d["permitir"], rol in porrol)
                    if rol not in porrol:
                        self.assertEqual(d["razon"], "defecto")

    def test_cada_condicion_violada_deniega_con_su_razon(self):
        politica = set(motor.matriz()["condiciones_politica"])
        for op, porrol in motor.matriz()["operaciones"].items():
            for rol, conds in porrol.items():
                for c in conds:
                    if c not in politica:
                        continue
                    with self.subTest(op=op, rol=rol, condicion=c):
                        d = motor.decidir(entrada(op, [rol], violar(c)))
                        self.assertFalse(d["permitir"])
                        self.assertEqual(d["razon"], c)

    def test_salida_de_una_concesion(self):
        d = motor.decidir(entrada("O1.Ap", ["R2"]))
        self.assertEqual(d["condiciones_servicio"], ["Cd7", "Cd8", "Cd10"])
        self.assertEqual(d["restricciones"], ["2fa_reciente"])
        r6 = motor.decidir(entrada("O3.L", ["R6"]))
        self.assertEqual(r6["proyeccion"], "dueno")
        r7 = motor.decidir(entrada("O1.L", ["R7"]))
        self.assertTrue(r7["registrar_lectura"])

    def test_emergencia(self):
        lectura = motor.decidir(entrada("O1.L", ["R7"], emergencia={"rol_suplido": "R2"}))
        self.assertTrue(lectura["permitir"])
        for op in ("O1.Ap", "O3.Ex", "O6.L", "O7.L", "O4.Au", "O3.An"):
            with self.subTest(op=op):
                self.assertEqual(motor.decidir(entrada(op, ["R7"], emergencia={"rol_suplido": "R2"}))["razon"], "Cd24")
        self.assertEqual(motor.decidir(entrada("O1.L", [], emergencia={"rol_suplido": "R7"}))["razon"], "Cd24")

    def test_entrada_invalida_deniega(self):
        self.assertEqual(motor.decidir({})["razon"], "defecto")
        self.assertEqual(motor.decidir({"operacion": "O1.L"})["razon"], "defecto")


class H2Tests(SimpleTestCase):
    def estado(self, wc, wl=0, laboral=True):
        return motor.estado_h2({"disponible": True, "ajena": True, "wc": wc, "wl": wl, "laboral": laboral}, PARAMETROS)

    def test_umbrales_laborales(self):
        self.assertEqual([self.estado(n) for n in (9, 10, 24, 25)], ["ok", "blando", "blando", "duro"])

    def test_umbrales_fuera_de_horario(self):
        self.assertEqual([self.estado(n, laboral=False) for n in (2, 3, 7, 8)], ["ok", "blando", "blando", "duro"])

    def test_ventana_larga(self):
        self.assertEqual([self.estado(1, n) for n in (39, 40, 99, 100)], ["ok", "blando", "blando", "duro"])

    def test_degradado_y_faltantes(self):
        self.assertEqual(motor.estado_h2({"disponible": False, "ajena": False}, PARAMETROS), "ok")
        self.assertEqual(motor.estado_h2({"disponible": False, "ajena": True}, PARAMETROS), "denegado")
        self.assertEqual(motor.estado_h2(None, PARAMETROS), "denegado")
        self.assertEqual(motor.estado_h2({"disponible": True, "ajena": True, "wc": 1, "wl": 1}, {}), "denegado")

    def test_horario_laboral(self):
        casos = {(1, 6): True, (5, 17): True, (5, 18): False, (1, 5): False, (6, 10): False, (7, 12): False}
        for (dia, hora), esperado in casos.items():
            with self.subTest(dia=dia, hora=hora):
                self.assertEqual(pip.es_laboral(dia, hora), esperado)


class MapaDeServiciosTests(SimpleTestCase):
    def test_operaciones_implementables_no_lectura_tienen_servicio(self):
        esperadas = {op for op, porrol in motor.matriz()["operaciones"].items() if porrol and motor.tipo_de(op) != "L"}
        self.assertEqual(set(pep.servicios()), esperadas)

    def test_condiciones_de_servicio_declaradas(self):
        de_servicio = set(motor.matriz()["condiciones_servicio"])
        for op, opciones in pep.servicios().items():
            exigidas = {c for conds in motor.matriz()["operaciones"][op].values() for c in conds if c in de_servicio}
            for nombre, (_, declaradas) in opciones.items():
                with self.subTest(op=op, servicio=nombre):
                    self.assertLessEqual(exigidas, declaradas)

    def test_todo_servicio_publico_esta_en_el_mapa_o_excluido(self):
        from catalogo import servicios as cat
        from mediciones import alertas
        from mediciones import servicios as med
        from usuarios import servicios as cue

        en_mapa = {f"{f.__module__}.{f.__name__}" for opciones in pep.servicios().values() for f, _ in opciones.values()}
        for modulo in (med, cat, cue, alertas):
            for nombre, valor in vars(modulo).items():
                if nombre.startswith("_") or not inspect.isfunction(valor) or valor.__module__ != modulo.__name__:
                    continue
                with self.subTest(funcion=f"{modulo.__name__}.{nombre}"):
                    completo = f"{modulo.__name__}.{nombre}"
                    self.assertTrue(completo in en_mapa or completo in pep.EXCLUIDOS)


class SesionTests(SimpleTestCase):
    def request(self, usuario=None, sesion=None):
        r = RequestFactory().get("/")
        r.user = usuario or mock.Mock(is_authenticated=False, is_active=False)
        r.session = sesion or {}
        return r

    def test_sesion_con_segundo_factor(self):
        usuario = mock.Mock(is_authenticated=True, is_active=True)
        momento = time.time() - 60
        s = pep.sesion_desde_request(self.request(usuario, {autenticacion.CLAVE_MFA: momento}))
        self.assertEqual((s.usuario, s.nivel_autenticacion, s.segundo_factor_en), (usuario, pep.NIVEL_SEGUNDO_FACTOR, momento))
        self.assertTrue(s.segundo_factor_reciente())

    def test_segundo_factor_viejo(self):
        usuario = mock.Mock(is_authenticated=True, is_active=True)
        s = pep.sesion_desde_request(self.request(usuario, {autenticacion.CLAVE_MFA: time.time() - 3600}))
        self.assertTrue(s.con_segundo_factor())
        self.assertFalse(s.segundo_factor_reciente())

    def test_preautenticada_y_anonima(self):
        pre = pep.sesion_desde_request(self.request(sesion={autenticacion.CLAVE_PRE_AUTH: {"usuario": "x"}}))
        self.assertEqual((pre.usuario, pre.nivel_autenticacion), (None, pep.NIVEL_CONTRASENA))
        anonima = pep.sesion_desde_request(self.request())
        self.assertEqual(anonima.nivel_autenticacion, pep.NIVEL_SIN_SESION)

    def test_emergencia_guardada(self):
        usuario = mock.Mock(is_authenticated=True, is_active=True)
        datos = {autenticacion.CLAVE_MFA: time.time(), pep.CLAVE_EMERGENCIA: {"rol_suplido": "R2", "vence_en": "2099-01-01T00:00:00+00:00"}}
        s = pep.sesion_desde_request(self.request(usuario, datos))
        self.assertEqual(s.emergencia["rol_suplido"], "R2")


class _Manejador(BaseHTTPRequestHandler):
    modo = "ok"

    def do_POST(self):
        largo = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(largo)
        if self.modo == "lento":
            time.sleep(3)
        if self.modo == "500":
            self.send_response(500)
            self.end_headers()
            return
        cuerpo = {
            "ok": json.dumps({"result": motor.denegar("defecto")}),
            "malformada": "{no es json",
            "incompleta": json.dumps({"result": {"permitir": True}}),
            "sin_resultado": json.dumps({}),
            "lento": json.dumps({"result": motor.denegar("defecto")}),
        }[self.modo].encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(cuerpo)

    def log_message(self, *args):
        pass


class ClienteOPATests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.servidor = ThreadingHTTPServer(("127.0.0.1", 0), _Manejador)
        cls.hilo = threading.Thread(target=cls.servidor.serve_forever, daemon=True)
        cls.hilo.start()
        cls.url = f"http://127.0.0.1:{cls.servidor.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.servidor.shutdown()
        cls.servidor.server_close()
        super().tearDownClass()

    def con_modo(self, modo):
        return mock.patch.object(_Manejador, "modo", modo)

    def test_respuesta_valida(self):
        with self.con_modo("ok"):
            self.assertFalse(pdp.ClienteOPA(self.url).decidir({})["permitir"])

    def test_fallas_lanzan_pdp_no_disponible(self):
        for modo in ("500", "malformada", "incompleta", "sin_resultado"):
            with self.subTest(modo=modo), self.con_modo(modo):
                with self.assertRaises(pdp.PDPNoDisponible):
                    pdp.ClienteOPA(self.url).decidir({})

    def test_timeout_de_dos_segundos(self):
        with self.con_modo("lento"):
            inicio = time.monotonic()
            with self.assertRaises(pdp.PDPNoDisponible):
                pdp.ClienteOPA(self.url).decidir({})
            self.assertLess(time.monotonic() - inicio, 2.9)

    def test_sin_servidor(self):
        with self.assertRaises(pdp.PDPNoDisponible):
            pdp.ClienteOPA("http://127.0.0.1:9").decidir({})

    def test_validar_decision(self):
        valida = motor.denegar("Cd9", ["cerrar_sesion"])
        self.assertEqual(pdp.validar_decision(valida), valida)
        for cambio in ({"permitir": "si"}, {"restricciones": ["otra"]}, {"razon": None}, {"extra": 1}):
            with self.subTest(cambio=cambio):
                with self.assertRaises(pdp.PDPNoDisponible):
                    pdp.validar_decision({**valida, **cambio})

    def test_selector(self):
        with mock.patch.dict("os.environ", {"PDP_BACKEND": "python"}):
            self.assertIsInstance(pdp.pdp_configurado(), pdp.MotorPython)
        with mock.patch.dict("os.environ", {"PDP_BACKEND": "opa"}):
            self.assertIsInstance(pdp.pdp_configurado(), pdp.ClienteOPA)
        with mock.patch.dict("os.environ", {"PDP_BACKEND": "otro"}):
            with self.assertRaises(ImproperlyConfigured):
                pdp.pdp_configurado()


class ConfiguracionTests(SimpleTestCase):
    def test_pep_exige_bitacora(self):
        with self.assertRaises(ImproperlyConfigured):
            pep.PEP(bitacora=None, pdp=pdp.MotorPython())
        self.assertIsInstance(pep.PEP(bitacora=BitacoraEnMemoria(), pdp=pdp.MotorPython()).bitacora, BitacoraEnMemoria)

    def test_bitacora_configurada(self):
        with override_settings(BITACORA_CLIENTE=None):
            with self.assertRaises(ImproperlyConfigured):
                bitacora_configurada()
        with override_settings(BITACORA_CLIENTE="autorizacion.bitacora.BitacoraEnMemoria"):
            self.assertIsInstance(bitacora_configurada(), BitacoraEnMemoria)

    def test_denegado_publico_es_generico(self):
        publico = pep.Denegado("Cd8", "detalle interno").publico()
        self.assertEqual(publico, {"permitido": False, "mensaje": pep.MENSAJE_GENERICO})
