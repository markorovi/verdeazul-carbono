"""Pruebas de la interfaz que no necesitan base de datos: estructura, proyecciones, redirección,
encabezados, IP del cliente, configuración segura por defecto y verificación pública."""

from __future__ import annotations

import ast
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django import forms
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.urls import URLPattern, URLResolver, get_resolver

from autorizacion import motor, pep
from interfaz import formularios, registro, serializadores, web
from interfaz.red import ip_cliente
from interfaz.redireccion import destino_seguro
from mediciones import firma
from mediciones import views as vistas_firma

RAIZ = Path(__file__).resolve().parent.parent
EXCLUIR = {".venv", "venv", ".git", "__pycache__", "node_modules"}
# Rutas sin sesión, explícitas y cortas: acceso, segundo factor, recuperación, salud, verificación
# pública, clave pública (página y JSON) y estáticos.
PUBLICAS = {"acceso", "segundo_factor", "recuperar", "salud", "verificar", "clave_publica",
            "clave_publica_pagina", "estatico"}
PROHIBIDOS_PY = ("csrf" + "_exempt", "mark" + "_safe", "Safe" + "String", "Safe" + "Text")
PROHIBIDO_PLANTILLA = re.compile(r"\|\s*safe\b|{%\s*autoescape\s+off")


def _archivos(sufijo: str):
    for ruta in RAIZ.rglob(f"*{sufijo}"):
        if not EXCLUIR.intersection(ruta.relative_to(RAIZ).parts):
            yield ruta


def _rutas(patrones=None, prefijo=""):
    for patron in patrones if patrones is not None else get_resolver().url_patterns:
        if isinstance(patron, URLResolver):
            yield from _rutas(patron.url_patterns, prefijo + str(patron.pattern))
        elif isinstance(patron, URLPattern):
            yield prefijo + str(patron.pattern), patron


def _clave_privada() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


class EstructuraTests(SimpleTestCase):
    def test_toda_ruta_esta_decorada_o_es_publica(self):
        sin_marca, publicas = [], set()
        for ruta, patron in _rutas():
            marca = getattr(patron.callback, web.MARCA, None)
            if marca is None:
                sin_marca.append(ruta)
            elif marca[0] == web.PUBLICA:
                publicas.add(patron.name)
        self.assertEqual(sin_marca, [], "rutas sin @operacion, @autenticada ni @publica")
        self.assertEqual(publicas, PUBLICAS)

    def test_las_rutas_de_operaciones_llevan_su_codigo(self):
        codigos = {getattr(p.callback, web.MARCA)[1] for _, p in _rutas()
                   if getattr(p.callback, web.MARCA, (None,))[0] == web.OPERACION}
        self.assertEqual(codigos, set(motor.matriz()["operaciones"]))

    def test_sin_exencion_csrf_ni_marcado_seguro_en_el_proyecto(self):
        hallazgos = [f"{r.relative_to(RAIZ)}: {p}" for r in _archivos(".py") for p in PROHIBIDOS_PY
                     if p in r.read_text(encoding="utf-8")]
        self.assertEqual(hallazgos, [])

    def test_plantillas_sin_safe_sin_scripts_ni_estilos_en_linea(self):
        hallazgos = []
        for ruta in _archivos(".html"):
            texto = ruta.read_text(encoding="utf-8")
            if PROHIBIDO_PLANTILLA.search(texto):
                hallazgos.append(f"{ruta.name}: safe o autoescape off")
            if re.search(r"<script|<style|\sstyle=|\son[a-z]+=", texto, re.IGNORECASE):
                hallazgos.append(f"{ruta.name}: script o estilo en línea")
        self.assertEqual(hallazgos, [])

    def test_sin_sql_armado_con_texto_en_interfaz(self):
        hallazgos = []
        for ruta in (RAIZ / "interfaz").rglob("*.py"):
            if "migrations" in ruta.parts:
                continue
            for nodo in ast.walk(ast.parse(ruta.read_text(encoding="utf-8"))):
                if (isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Attribute)
                        and nodo.func.attr in ("execute", "executemany", "raw", "extra") and nodo.args):
                    primero = nodo.args[0]
                    armado = isinstance(primero, (ast.JoinedStr, ast.BinOp)) or (
                        isinstance(primero, ast.Call) and isinstance(primero.func, ast.Attribute)
                        and primero.func.attr == "format")
                    if armado:
                        hallazgos.append(f"{ruta.name}:{nodo.lineno}")
        self.assertEqual(hallazgos, [])

    def test_formularios_explicitos_sin_modelform(self):
        for entrada in registro.ENTRADAS:
            if entrada.formulario is not None:
                self.assertTrue(issubclass(entrada.formulario, forms.Form))
                self.assertFalse(issubclass(entrada.formulario, forms.ModelForm))
        fuente = "\n".join(r.read_text(encoding="utf-8") for r in (RAIZ / "interfaz").rglob("*.py") if r.name != "tests.py")
        self.assertNotIn("__all__", fuente)
        self.assertNotIn("model_to_dict", fuente)


class RegistroTests(SimpleTestCase):
    def test_cubre_las_41_operaciones(self):
        matriz = motor.matriz()["operaciones"]
        self.assertEqual(set(registro.CODIGOS), set(matriz))
        self.assertEqual(len(matriz), 41)
        denegadas = {e.codigo for e in registro.ENTRADAS if e.clase == registro.DENEGADA}
        self.assertEqual(denegadas, {c for c, permisos in matriz.items() if not permisos})
        self.assertEqual(len(denegadas), 9)
        implementables = {e.codigo for e in registro.ENTRADAS if e.clase != registro.DENEGADA}
        self.assertEqual(len(implementables), 32)

    def test_cada_escritura_usa_un_servicio_del_mapa_del_pep(self):
        mapa = pep.servicios()
        for entrada in registro.ENTRADAS:
            if entrada.clase == registro.ESCRITURA:
                self.assertIn(entrada.servicio, mapa[entrada.codigo], entrada.clave)
        usados = {(e.codigo, e.servicio) for e in registro.ENTRADAS if e.clase == registro.ESCRITURA}
        self.assertEqual(usados, {(c, s) for c, servicios in mapa.items() for s in servicios})


class ProyeccionTests(SimpleTestCase):
    def test_solo_se_evaluan_los_campos_proyectados(self):
        def prohibido():
            raise AssertionError("campo fuera de la proyección evaluado")

        valores = {c: prohibido for c in serializadores.PROYECCIONES["medicion"][serializadores.COMPLETA]}
        for campo in serializadores.PROYECCIONES["medicion"]["dueno"]:
            valores[campo] = lambda: "x"
        ficha = serializadores._ficha("medicion", "id-1", "dueno", valores)
        self.assertEqual(ficha.claves(), set(serializadores.PROYECCIONES["medicion"]["dueno"]))
        self.assertNotIn("notas", ficha.claves())
        self.assertNotIn("huella", ficha.claves())

    def test_las_proyecciones_reducen_campos(self):
        p = serializadores.PROYECCIONES
        self.assertLess(set(p["certificado"]["dueno"]), set(p["certificado"][serializadores.COMPLETA]))
        self.assertLess(set(p["certificado"]["tecnico"]), set(p["certificado"][serializadores.COMPLETA]))
        self.assertNotIn("correo", p["cuenta"]["auditor"])
        self.assertNotIn("id", p["cuenta"]["auditor"])

    def test_proyeccion_desconocida_deniega(self):
        with self.assertRaises(serializadores.ProyeccionNoDisponible):
            serializadores.campos_de("medicion", "auditor")
        with self.assertRaises(serializadores.ProyeccionNoDisponible):
            serializadores.campos_de("inexistente", None)

    def test_toda_proyeccion_de_la_politica_existe_en_algun_objeto(self):
        declaradas = {n for t in serializadores.PROYECCIONES.values() for n in t}
        politica = set(motor.politica()["proyecciones"].values())
        politica |= {v for por_rol in motor.politica()["proyecciones_por_operacion"].values() for v in por_rol.values()}
        self.assertLessEqual(politica, declaradas)

    def test_la_ficha_no_expone_el_id_si_la_proyeccion_no_lo_tiene(self):
        valores = {c: (lambda: "v") for c in serializadores.PROYECCIONES["cuenta"][serializadores.COMPLETA] + ("seudonimo",)}
        ficha = serializadores._ficha("cuenta", "uuid-1", "auditor", valores)
        self.assertIsNone(ficha.objeto_id)


class RedireccionTests(SimpleTestCase):
    def test_rechaza_destinos_externos(self):
        for valor in ("https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)",
                      "http:/x", " /cuenta/", "/cuenta/\r\nX: y", "", None, "/no-existe/", "cuenta/"):
            self.assertEqual(destino_seguro(valor), "/cuenta/", repr(valor))

    def test_acepta_rutas_internas(self):
        self.assertEqual(destino_seguro("/operaciones/"), "/operaciones/")
        self.assertEqual(destino_seguro("/mediciones/?pagina=2"), "/mediciones/?pagina=2")


class EncabezadosTests(SimpleTestCase):
    def test_encabezados_de_seguridad(self):
        r = self.client.get("/verificar/")
        self.assertIn("default-src 'self'", r["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", r["Content-Security-Policy"])
        self.assertEqual(r["X-Frame-Options"], "DENY")
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r["Referrer-Policy"], "same-origin")
        self.assertIn("camera=()", r["Permissions-Policy"])
        self.assertEqual(r["Cache-Control"], "no-store")

    def test_la_hoja_de_estilos_se_sirve_y_lo_demas_no(self):
        r = self.client.get("/estaticos/interfaz/estilo.css")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r["Content-Type"].startswith("text/css"))
        self.assertEqual(self.client.get("/estaticos/../config/settings.py").status_code, 404)
        self.assertEqual(self.client.get("/estaticos/interfaz/otro.css").status_code, 404)

    def test_cuerpo_demasiado_grande(self):
        r = self.client.generic("POST", "/verificar/", b"x", CONTENT_TYPE="text/plain",
                                CONTENT_LENGTH=str(1024 * 1024))
        self.assertEqual(r.status_code, 413)

    @override_settings(DEBUG=False)
    def test_404_generico_sin_trazas(self):
        r = self.client.get("/ruta/que/no/existe/")
        contenido = r.content.decode()
        self.assertEqual(r.status_code, 404)
        self.assertIn("La página solicitada no existe.", contenido)
        self.assertNotIn("Traceback", contenido)
        self.assertNotIn("urlpatterns", contenido)

    def test_csrf_fallido_es_generico(self):
        cliente = self.client_class(enforce_csrf_checks=True)
        r = cliente.post("/verificar/", {"certificado": "{}"})
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("CSRF", r.content.decode())

    def test_sin_sesion_redirige_al_acceso(self):
        self.assertEqual(self.client.get("/operaciones/").status_code, 302)
        self.assertTrue(self.client.get("/operaciones/")["Location"].startswith("/acceso/?next="))


class IPTests(SimpleTestCase):
    def _request(self, xff=None, remota="10.0.0.9"):
        meta = {"REMOTE_ADDR": remota}
        if xff is not None:
            meta["HTTP_X_FORWARDED_FOR"] = xff
        return RequestFactory().get("/", **meta)

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_toma_la_ultima_entrada_nunca_la_primera(self):
        self.assertEqual(ip_cliente(self._request("1.2.3.4, 203.0.113.7")), "203.0.113.7")
        self.assertEqual(ip_cliente(self._request("203.0.113.7")), "203.0.113.7")

    @override_settings(TRUSTED_PROXY_COUNT=2)
    def test_con_dos_proxies_la_penultima(self):
        self.assertEqual(ip_cliente(self._request("1.1.1.1, 203.0.113.7, 10.1.1.1")), "203.0.113.7")
        self.assertEqual(ip_cliente(self._request("203.0.113.7")), "10.0.0.9")

    @override_settings(TRUSTED_PROXY_COUNT=1)
    def test_sin_encabezado_o_invalido_usa_remote_addr(self):
        self.assertEqual(ip_cliente(self._request()), "10.0.0.9")
        self.assertEqual(ip_cliente(self._request("no-es-ip")), "10.0.0.9")

    @override_settings(TRUSTED_PROXY_COUNT=0)
    def test_sin_proxies_ignora_el_encabezado(self):
        self.assertEqual(ip_cliente(self._request("203.0.113.7")), "10.0.0.9")


class ConfiguracionSeguraTests(SimpleTestCase):
    def _ajustes(self, **entorno) -> dict:
        codigo = (
            "import json, django\nfrom django.conf import settings\n"
            "django.setup()\n"
            "print(json.dumps({k: getattr(settings, k) for k in ('DEBUG', 'SECURE_SSL_REDIRECT', 'SESSION_COOKIE_SECURE',"
            " 'CSRF_COOKIE_SECURE', 'SECURE_HSTS_SECONDS', 'SESSION_COOKIE_HTTPONLY', 'SESSION_COOKIE_SAMESITE',"
            " 'ALLOWED_HOSTS', 'CSRF_TRUSTED_ORIGINS', 'BITACORA_TIMEOUT', 'PDP_TIMEOUT', 'TRUSTED_PROXY_COUNT',"
            " 'LISTA_TAMANO_PAGINA', 'SECURE_HSTS_INCLUDE_SUBDOMAINS', 'SECURE_PROXY_SSL_HEADER')}))"
        )
        base = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "DJANGO_SETTINGS_MODULE": "config.settings", "SECRET_KEY": "clave-de-prueba-de-configuracion",
                "DATABASE_URL": "postgres://ficticio@127.0.0.1:1/ficticio"}
        proceso = subprocess.run([sys.executable, "-c", codigo], cwd=RAIZ, env={**base, **entorno},
                                 capture_output=True, text=True, timeout=120)
        return json.loads(proceso.stdout) if proceso.returncode == 0 else {"error": proceso.returncode}

    def test_sin_entorno_es_produccion_estricta(self):
        a = self._ajustes()
        self.assertFalse(a["DEBUG"])
        self.assertTrue(a["SECURE_SSL_REDIRECT"] and a["SESSION_COOKIE_SECURE"] and a["CSRF_COOKIE_SECURE"])
        self.assertGreaterEqual(a["SECURE_HSTS_SECONDS"], 31536000)
        self.assertTrue(a["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(a["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertEqual(a["ALLOWED_HOSTS"], [])
        self.assertEqual(a["CSRF_TRUSTED_ORIGINS"], [])
        self.assertEqual((a["BITACORA_TIMEOUT"], a["PDP_TIMEOUT"], a["TRUSTED_PROXY_COUNT"]), (2.0, 2.0, 1))
        self.assertTrue(a["SECURE_HSTS_INCLUDE_SUBDOMAINS"])
        self.assertEqual(a["SECURE_PROXY_SSL_HEADER"], ["HTTP_X_FORWARDED_PROTO", "https"])
        self.assertEqual(a["LISTA_TAMANO_PAGINA"], 10)

    def test_hosts_y_timeouts_por_variables(self):
        a = self._ajustes(ALLOWED_HOSTS="app.example, otra.example", CSRF_TRUSTED_ORIGINS="https://app.example",
                          BITACORA_TIMEOUT="3.5", PDP_TIMEOUT="1")
        self.assertEqual(a["ALLOWED_HOSTS"], ["app.example", "otra.example"])
        self.assertEqual(a["CSRF_TRUSTED_ORIGINS"], ["https://app.example"])
        self.assertEqual((a["BITACORA_TIMEOUT"], a["PDP_TIMEOUT"]), (3.5, 1.0))

    def test_tamano_de_pagina_por_variable_con_tope(self):
        self.assertEqual(self._ajustes(LISTA_TAMANO_PAGINA="5")["LISTA_TAMANO_PAGINA"], 5)
        self.assertIn("error", self._ajustes(LISTA_TAMANO_PAGINA="21"))
        self.assertIn("error", self._ajustes(LISTA_TAMANO_PAGINA="0"))

    def test_timeout_fuera_de_rango_no_arranca(self):
        self.assertIn("error", self._ajustes(PDP_TIMEOUT="60"))
        self.assertIn("error", self._ajustes(BITACORA_TIMEOUT="abc"))


class TraduccionTests(SimpleTestCase):
    def test_motivos_de_infraestructura_existen_en_el_pep(self):
        fuente = (RAIZ / "autorizacion" / "pep.py").read_text(encoding="utf-8")
        for motivo in pep.MOTIVOS_DE_INFRAESTRUCTURA:
            self.assertGreaterEqual(fuente.count(f'"{motivo}"'), 2, motivo)

    def test_infraestructura_es_503_y_politica_403(self):
        self.assertTrue(web.es_de_infraestructura(pep.Denegado("defecto", "falla del PDP")))
        self.assertTrue(web.es_de_infraestructura(pep.Denegado("Cd17", "política")))
        self.assertFalse(web.es_de_infraestructura(pep.Denegado("Cd2", "política")))
        self.assertFalse(web.es_de_infraestructura(pep.Denegado("defecto", "política")))

    def test_hay_motivo_breve_para_cada_condicion(self):
        condiciones = set(motor.matriz()["condiciones_politica"]) | set(motor.matriz()["condiciones_servicio"])
        self.assertLessEqual(condiciones | {"defecto"}, set(web.MOTIVOS_BREVES))


class VerificacionTests(SimpleTestCase):
    def setUp(self):
        self.propia = _clave_privada()
        self.otra = _clave_privada()
        self.huella = firma.huella_publica(self.propia)

    def _texto(self, clave) -> str:
        payload = firma.construir_payload(
            "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", 1, "100.000", "a" * 64,
            ["55555555-5555-4555-8555-555555555555"], firma_fecha(), clave=clave)
        return json.dumps(firma.firmar(payload, clave))

    def test_cuatro_conclusiones(self):
        valido = self._texto(self.propia)
        self.assertEqual(vistas_firma.evaluar(valido, self.huella)["conclusion"], vistas_firma.INTEGRO_VERDEAZUL)
        self.assertEqual(vistas_firma.evaluar(self._texto(self.otra), self.huella)["conclusion"],
                         vistas_firma.INTEGRO_OTRA_CLAVE)
        alterado = json.loads(valido)
        alterado["payload"]["co2e_toneladas"] = "100.001"
        self.assertEqual(vistas_firma.evaluar(json.dumps(alterado), self.huella)["conclusion"], vistas_firma.ALTERADO)
        self.assertEqual(vistas_firma.evaluar("{no es json", self.huella)["conclusion"], vistas_firma.FORMATO_INVALIDO)
        self.assertEqual(vistas_firma.evaluar("[]", self.huella)["conclusion"], vistas_firma.FORMATO_INVALIDO)

    def test_integridad_y_emisor_por_separado(self):
        otra = vistas_firma.evaluar(self._texto(self.otra), self.huella)
        self.assertEqual((otra["integridad"], otra["emisor"]), (True, False))
        propia = vistas_firma.evaluar(self._texto(self.propia), self.huella)
        self.assertEqual((propia["integridad"], propia["emisor"]), (True, True))

    def _exportado(self, clave, **cambios) -> dict:
        """Misma forma que el archivo de la exportación O3.Ex."""
        return {"certificado": json.loads(self._texto(clave)), "estado": "vigente",
                "trazabilidad": [{"etapa": "registro", "rol": "R1", "fecha": "2026-01-10T12:00:00Z",
                                  "resultado": "registrada", "actor": "0" * 16}], **cambios}

    def test_archivo_exportado_completo(self):
        valido = vistas_firma.evaluar(json.dumps(self._exportado(self.propia)), self.huella)
        self.assertEqual((valido["conclusion"], valido["integridad"], valido["emisor"], valido["envoltorio"]),
                         (vistas_firma.INTEGRO_VERDEAZUL, True, True, True))
        otra = vistas_firma.evaluar(json.dumps(self._exportado(self.otra)), self.huella)
        self.assertEqual(otra["conclusion"], vistas_firma.INTEGRO_OTRA_CLAVE)
        alterado = self._exportado(self.propia)
        alterado["certificado"]["payload"]["co2e_toneladas"] = "100.001"
        self.assertEqual(vistas_firma.evaluar(json.dumps(alterado), self.huella)["conclusion"], vistas_firma.ALTERADO)

    def test_archivo_exportado_con_claves_de_mas_o_de_menos(self):
        extra = self._exportado(self.propia, nota="x")
        faltante = self._exportado(self.propia)
        del faltante["trazabilidad"]
        for caso in (extra, faltante):
            r = vistas_firma.evaluar(json.dumps(caso), self.huella)
            self.assertEqual((r["conclusion"], r["envoltorio"]), (vistas_firma.FORMATO_INVALIDO, False))

    def test_estado_y_trazabilidad_no_cambian_el_resultado(self):
        base = vistas_firma.evaluar(json.dumps(self._exportado(self.propia)), self.huella)
        cambiado = vistas_firma.evaluar(json.dumps(self._exportado(
            self.propia, estado="anulado", trazabilidad=[{"etapa": "inventada"}])), self.huella)
        self.assertEqual(base, cambiado)

    def test_objeto_interno_igual_que_antes(self):
        r = vistas_firma.evaluar(self._texto(self.propia), self.huella)
        self.assertEqual(r, {"conclusion": vistas_firma.INTEGRO_VERDEAZUL, "estado": firma.ESTADO_VALIDO,
                             "integridad": True, "emisor": True, "envoltorio": False})

    def test_la_linea_informativa_solo_con_envoltorio(self):
        semilla = base64.b64encode(self.propia.private_bytes_raw()).decode()
        firma.clave_privada.cache_clear()
        try:
            with mock.patch.dict(os.environ, {firma.VARIABLE_CLAVE: semilla}):
                con = self.client.post("/verificar/", {"certificado": json.dumps(self._exportado(self.propia))})
                sin = self.client.post("/verificar/", {"certificado": self._texto(self.propia)})
        finally:
            firma.clave_privada.cache_clear()
        self.assertEqual((con.status_code, sin.status_code), (200, 200))
        self.assertIn(vistas_firma.AVISO_ENVOLTORIO, con.content.decode())
        self.assertIn(vistas_firma.CONCLUSIONES[vistas_firma.INTEGRO_VERDEAZUL], con.content.decode())
        self.assertNotIn(vistas_firma.AVISO_ENVOLTORIO, sin.content.decode())
        self.assertIn(vistas_firma.CONCLUSIONES[vistas_firma.INTEGRO_VERDEAZUL], sin.content.decode())

    def test_la_pagina_no_repite_el_texto_enviado(self):
        semilla = base64.b64encode(self.propia.private_bytes_raw()).decode()
        firma.clave_privada.cache_clear()
        try:
            with mock.patch.dict(os.environ, {firma.VARIABLE_CLAVE: semilla}):
                marca = "<script>marca-de-prueba</script>"
                r = self.client.post("/verificar/", {"certificado": marca})
                self.assertEqual(r.status_code, 200)
                self.assertNotIn("marca-de-prueba", r.content.decode())
        finally:
            firma.clave_privada.cache_clear()


def firma_fecha():
    from datetime import datetime, timezone

    return datetime(2026, 1, 15, tzinfo=timezone.utc)


class ProxyHttpsTests(SimpleTestCase):
    """Detrás de Cloud Run: TLS termina en el proxy, que envía X-Forwarded-Proto: https."""

    def _salud(self, **meta):
        conexion = mock.MagicMock()
        with mock.patch("interfaz.vistas.connection", conexion):
            return self.client.get("/salud/", HTTP_HOST="app.example", **meta)

    @override_settings(SECURE_SSL_REDIRECT=True, SECURE_HSTS_SECONDS=31536000, ALLOWED_HOSTS=["app.example"])
    def test_sin_cabecera_redirige_a_https(self):
        r = self._salud()
        self.assertEqual(r.status_code, 301)
        self.assertEqual(r["Location"], "https://app.example/salud/")

    @override_settings(SECURE_SSL_REDIRECT=True, SECURE_HSTS_SECONDS=31536000, ALLOWED_HOSTS=["app.example"])
    def test_con_cabecera_https_responde_200_sin_bucle(self):
        r = self._salud(HTTP_X_FORWARDED_PROTO="https")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"estado": "ok"})
        self.assertNotIn("Location", r)
        self.assertIn("max-age=31536000", r["Strict-Transport-Security"])

    @override_settings(SECURE_SSL_REDIRECT=True, ALLOWED_HOSTS=["app.example"])
    def test_seguir_la_redireccion_por_el_proxy_no_vuelve_a_redirigir(self):
        primera = self._salud(HTTP_X_FORWARDED_PROTO="http")
        self.assertEqual(primera.status_code, 301)
        segunda = self._salud(HTTP_X_FORWARDED_PROTO="https")
        self.assertEqual(segunda.status_code, 200)

    def test_la_cabecera_de_confianza_es_x_forwarded_proto(self):
        from django.conf import settings

        self.assertEqual(settings.SECURE_PROXY_SSL_HEADER, ("HTTP_X_FORWARDED_PROTO", "https"))


class TamanoDePaginaTests(SimpleTestCase):
    def _pagina(self, consulta=""):
        from interfaz import vistas

        return vistas._paginacion(RequestFactory().get(f"/mediciones/{consulta}"))

    @override_settings(LISTA_TAMANO_PAGINA=10)
    def test_por_defecto_10(self):
        self.assertEqual(self._pagina(), (1, 10))
        self.assertEqual(self._pagina("?tamano=20"), (1, 10))
        self.assertEqual(self._pagina("?tamano=3&pagina=2"), (2, 3))

    @override_settings(LISTA_TAMANO_PAGINA=4)
    def test_el_valor_configurado_es_el_tope(self):
        self.assertEqual(self._pagina(), (1, 4))
        self.assertEqual(self._pagina("?tamano=20"), (1, 4))
        self.assertEqual(self._pagina("?tamano=no"), (1, 4))
