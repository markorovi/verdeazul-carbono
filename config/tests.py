"""Pruebas del proyecto que no necesitan base de datos."""

import sys

from django.test import RequestFactory, SimpleTestCase
from django.views.debug import (
    ExceptionReporter,
    SafeExceptionReporterFilter,
    get_default_exception_reporter_filter,
)

VALOR_FALSO = "valor-falso-de-prueba"


def html_reporte_error(filtro=None) -> str:
    """HTML del reporte técnico de error para un request con DATABASE_URL en META.

    Si se indica `filtro`, se usa ese filtro para el request en lugar del configurado.
    """
    request = RequestFactory().get("/")
    request.META["DATABASE_URL"] = VALOR_FALSO
    if filtro is not None:
        request.exception_reporter_filter = filtro
    try:
        raise RuntimeError("error de prueba")
    except RuntimeError:
        reporte = ExceptionReporter(request, *sys.exc_info())
    return reporte.get_traceback_html()


class FiltroReporteSeguroTests(SimpleTestCase):
    def setUp(self):
        # Django guarda en caché el filtro por defecto; se limpia para leer la configuración actual.
        get_default_exception_reporter_filter.cache_clear()

    def test_oculta_database_url_en_el_reporte(self):
        self.assertNotIn(VALOR_FALSO, html_reporte_error())

    def test_el_filtro_estandar_lo_mostraria(self):
        """Control: con el filtro estándar de Django el valor sí aparece."""
        self.assertIn(VALOR_FALSO, html_reporte_error(SafeExceptionReporterFilter()))


def _escaner():
    import importlib.util
    from pathlib import Path

    ruta = Path(__file__).resolve().parent.parent / "scripts" / "escanear_secretos.py"
    especificacion = importlib.util.spec_from_file_location("escanear_secretos", ruta)
    modulo = importlib.util.module_from_spec(especificacion)
    especificacion.loader.exec_module(modulo)
    return modulo


class EscanerDeSecretosTests(SimpleTestCase):
    """Los valores sintéticos se arman en tiempo de ejecución para que este archivo no los contenga."""

    def setUp(self):
        import secrets

        self.escaner = _escaner()
        self.aleatorio = secrets.token_urlsafe(32)

    def test_detecta_las_tres_reglas(self):
        texto = "\n".join([
            "x = 1",
            "URL = 'postgresql://app:" + self.aleatorio + "@servidor.example/base'",
            "-" * 5 + "BEGIN " + "PRIVATE KEY" + "-" * 5,
            "BITACORA_SALT = \"" + self.aleatorio + "\"",
        ])
        self.assertEqual(self.escaner.analizar_texto(texto),
                         [(2, "cadena_conexion"), (3, "clave_privada_pem"), (4, "asignacion_secreta")])

    def test_ignora_ejemplos_y_valores_de_baja_entropia(self):
        texto = "\n".join([
            "postgres://usuario:contrasena@host/base",
            "postgres://ficticio@127.0.0.1:1/ficticio",
            "SECRET_KEY = 'clave-de-prueba-de-configuracion'",
            "token = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
            "nombre = '" + self.aleatorio + "'",
        ])
        self.assertEqual(self.escaner.analizar_texto(texto), [])

    def test_no_devuelve_el_valor(self):
        resultado = repr(self.escaner.analizar_texto("password = '" + self.aleatorio + "'"))
        self.assertNotIn(self.aleatorio, resultado)
        self.assertIn("asignacion_secreta", resultado)


class ImagenesTests(SimpleTestCase):
    """Revisión estática de los Dockerfiles y de .dockerignore (sin construir imágenes)."""

    def _leer(self, relativa: str) -> str:
        from pathlib import Path

        return (Path(__file__).resolve().parent.parent / relativa).read_text(encoding="utf-8")

    def test_bases_con_version_y_digest(self):
        import re

        for ruta in ("Dockerfile", "deploy/opa/Dockerfile", "deploy/bitacora/Dockerfile"):
            desde = [l for l in self._leer(ruta).splitlines() if l.startswith("FROM ")]
            self.assertEqual(len(desde), 1, ruta)
            self.assertRegex(desde[0], r"^FROM [a-z0-9/._-]+:[0-9][A-Za-z0-9._-]*@sha256:[0-9a-f]{64}$", ruta)
            self.assertNotIn("latest", desde[0])
        for ruta in ("Dockerfile", "deploy/bitacora/Dockerfile"):
            self.assertIn("python:3.13.7-", self._leer(ruta))
            self.assertTrue(re.search(r"^USER 10001:10001$", self._leer(ruta), re.MULTILINE), ruta)
        self.assertIn("USER 65532:65532", self._leer("deploy/opa/Dockerfile"))
        self.assertIn("--addr=0.0.0.0:8080", self._leer("deploy/opa/Dockerfile"))

    def test_sin_salto_de_linea_literal(self):
        """Un "\\n" literal fuera de comentarios rompe la instrucción (p. ej. un ENV de varias líneas)."""
        from pathlib import Path

        raiz = Path(__file__).resolve().parent.parent
        archivos = [raiz / "Dockerfile", *sorted((raiz / "deploy").rglob("Dockerfile*"))]
        self.assertGreaterEqual(len(archivos), 3)
        for archivo in archivos:
            for numero, linea in enumerate(archivo.read_text(encoding="utf-8").splitlines(), start=1):
                if linea.lstrip().startswith("#"):
                    continue
                self.assertNotIn("\\n", linea, f"{archivo.relative_to(raiz).as_posix()}:{numero}")

    def test_gunicorn_de_la_aplicacion(self):
        cmd = [l for l in self._leer("Dockerfile").splitlines() if l.startswith("CMD ")][0]
        for parte in ("${PORT:-8080}", "--workers 2", "--threads 4", "--timeout 60"):
            self.assertIn(parte, cmd)

    def test_dockerignore_excluye_lo_sensible(self):
        lineas = set(self._leer(".dockerignore").splitlines())
        for patron in (".git", ".venv", ".env", ".env*", ".opa_local.json", "**/*.pem", "**/*.key", "scripts/",
                       "requirements-dev.txt", "CLAUDE.md"):
            self.assertIn(patron, lineas)
        self.assertNotIn("bandit", self._leer("requirements.txt").lower())

    def test_gitignore_cubre_credenciales(self):
        lineas = set(self._leer(".gitignore").splitlines())
        for patron in (".env", ".env.*", "*.pem", "*.key", ".opa_local.json", "credenciales_demo*"):
            self.assertIn(patron, lineas)
