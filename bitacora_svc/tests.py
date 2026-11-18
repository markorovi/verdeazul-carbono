"""Pruebas del servicio de bitácora que no necesitan base: contrato, hash, seudónimo, llaves, puntos,
almacén local y códigos de salida del verificador independiente (scripts/verify_bitacora.py)."""

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from bitacora_svc import almacen, claves, contrato, puntos

RAIZ = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("verify_bitacora", RAIZ / "scripts" / "verify_bitacora.py")
verify_bitacora = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_bitacora)

EVENTO = {"accion": "intento", "origen": "pep", "resultado": "concedido", "operacion": "O1.Ap"}


def semilla_b64(llave: Ed25519PrivateKey) -> str:
    return base64.b64encode(llave.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode("ascii")


def cadena(n: int, llave: Ed25519PrivateKey, cada: int = 5) -> tuple[list[dict], dict[int, dict]]:
    """Cadena sintética de n eventos y sus puntos cada `cada`, con la fórmula del contrato."""
    eventos, documentos, previo = [], {}, contrato.CEROS
    for seq in range(1, n + 1):
        cuerpo = {**EVENTO, "seq": seq, "sello": f"2099-01-01T00:00:{seq % 60:02d}.000000Z", "clase": "certificacion"}
        hash_evento = contrato.calcular_hash(previo, contrato.canonico(cuerpo))
        eventos.append({**cuerpo, "hash_previo": previo, "hash": hash_evento})
        if seq % cada == 0:
            documentos[seq] = puntos.documento(llave, seq, hash_evento, "2099-01-01T00:01:00.000000Z")
        previo = hash_evento
    return eventos, documentos


class ContratoTests(unittest.TestCase):
    def test_canonico(self):
        self.assertEqual(contrato.canonico({"b": 1, "a": "ñ"}), '{"a":"ñ","b":1}'.encode("utf-8"))

    def test_formula_del_hash(self):
        cuerpo = {"accion": "lectura", "seq": 1}
        esperado = hashlib.sha256(b"0" * 64 + b'{"accion":"lectura","seq":1}').hexdigest()
        self.assertEqual(contrato.calcular_hash(contrato.CEROS, contrato.canonico(cuerpo)), esperado)
        self.assertEqual(contrato.hash_de_evento({**cuerpo, "hash_previo": contrato.CEROS, "hash": "x"}), esperado)

    def test_ignora_campos_del_servicio(self):
        validado = contrato.validar({**EVENTO, "seq": 99, "sello": "falso", "hash": "f" * 64, "fecha": "x", "clase": "consulta"})
        self.assertEqual(validado, EVENTO)

    def test_rechazos(self):
        casos = [
            {**EVENTO, "desconocido": "x"},
            {**EVENTO, "operacion": 5},
            {**EVENTO, "accion": "borrar"},
            {**EVENTO, "objeto_id": "x" * 65},
            {"accion": "intento", "origen": "pep"},
            {"accion": "intento", "origen": "pep", "resultado": "concedido"},
            ["no", "es", "objeto"],
        ]
        for caso in casos:
            with self.subTest(caso=str(caso)[:40]):
                with self.assertRaises(contrato.EventoInvalido):
                    contrato.validar(caso)

    def test_cuerpo_excesivo_y_no_json(self):
        with self.assertRaises(contrato.EventoInvalido):
            contrato.decodificar_cuerpo(b"{" + b" " * contrato.MAX_BYTES_CUERPO + b"}")
        with self.assertRaises(contrato.EventoInvalido):
            contrato.decodificar_cuerpo(b"no es json")

    def test_clases(self):
        casos = {
            ("intento", "O1.Ap"): "certificacion", ("resultado", "O2.Ci"): "certificacion",
            ("intento", "O3.Ex"): "consulta", ("intento", "O6.AR"): "administracion",
            ("lectura", None): "consulta", ("denegacion", None): "acceso",
            ("inicio_sesion", None): "acceso", ("version_politica", None): "administracion",
        }
        for (accion, operacion), clase in casos.items():
            with self.subTest(accion=accion, operacion=operacion):
                evento = {"accion": accion, **({"operacion": operacion} if operacion else {})}
                self.assertEqual(contrato.clase_de(evento), clase)

    def test_seudonimo(self):
        sal, otra = os.urandom(32), os.urandom(32)
        a = contrato.seudonimo(sal, "usuario-a")
        self.assertEqual(len(a), 32)
        self.assertEqual(a, contrato.seudonimo(sal, "usuario-a"))
        self.assertNotEqual(a, contrato.seudonimo(sal, "usuario-b"))
        self.assertNotEqual(a, contrato.seudonimo(otra, "usuario-a"))


class LlavesTests(unittest.TestCase):
    def test_semilla_valida_con_salto_de_linea(self):
        llave = Ed25519PrivateKey.generate()
        cargada = claves.cargar_llave(semilla_b64(llave) + "\n")
        self.assertEqual(claves.huella_publica(cargada), claves.huella_publica(llave))
        self.assertEqual(len(claves.key_id(llave)), 16)

    def test_errores_sin_el_valor(self):
        corta = base64.b64encode(os.urandom(16)).decode("ascii")
        for valor in ("", corta, "no-es-base64!!"):
            with self.subTest(largo=len(valor)):
                with self.assertRaises(claves.LlaveNoConfigurada) as contexto:
                    claves.cargar_llave(valor)
                if valor:
                    self.assertNotIn(valor, str(contexto.exception))
        with self.assertRaises(claves.LlaveNoConfigurada):
            claves.cargar_sal(corta)


class PuntosYAlmacenTests(unittest.TestCase):
    def setUp(self):
        self.carpeta = tempfile.mkdtemp(prefix="bitacora_unit_")

    def tearDown(self):
        shutil.rmtree(self.carpeta, ignore_errors=True)

    def test_firma_y_clave_confiable(self):
        llave, ajena = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        doc = puntos.documento(llave, 5, "a" * 64, "2099-01-01T00:00:00.000000Z")
        self.assertTrue(puntos.firma_valida(doc, claves.huella_publica(llave)))
        self.assertFalse(puntos.firma_valida(doc, claves.huella_publica(ajena)))
        alterado = json.loads(json.dumps(doc))
        alterado["payload"]["hash"] = "b" * 64
        self.assertFalse(puntos.firma_valida(alterado, claves.huella_publica(llave)))

    def test_almacen_local_no_sobrescribe(self):
        local = almacen.AlmacenLocal(self.carpeta)
        local.guardar(25, b"uno")
        with self.assertRaises(almacen.YaExiste):
            local.guardar(25, b"dos")
        self.assertEqual(local.leer(25), b"uno")
        self.assertEqual(local.listar(), [25])
        self.assertTrue((Path(self.carpeta) / "puntos" / "000000000025.json").exists())


class VerificadorTests(unittest.TestCase):
    def setUp(self):
        self.carpeta = Path(tempfile.mkdtemp(prefix="bitacora_verificador_"))
        self.llave = Ed25519PrivateKey.generate()
        self.huella = claves.huella_publica(self.llave)

    def tearDown(self):
        shutil.rmtree(self.carpeta, ignore_errors=True)

    def escribir(self, eventos, documentos, crudo: bytes | None = None) -> int:
        archivo = self.carpeta / "eventos.jsonl"
        archivo.write_bytes(crudo if crudo is not None else b"".join(contrato.canonico(e) + b"\n" for e in eventos))
        destino = self.carpeta / "puntos"
        shutil.rmtree(destino, ignore_errors=True)
        destino.mkdir()
        for seq, doc in documentos.items():
            (destino / f"{seq:012d}.json").write_bytes(contrato.canonico(doc))
        return verify_bitacora.main(["--eventos", str(archivo), "--puntos", str(self.carpeta), "--huella", self.huella, "--cada", "5"])

    def test_codigos_de_salida(self):
        eventos, documentos = cadena(12, self.llave)
        self.assertEqual(self.escribir(eventos, documentos), 0)

        alterados = json.loads(json.dumps(eventos))
        alterados[3]["resultado"] = "denegado"
        self.assertEqual(self.escribir(alterados, documentos), 1)

        con_hueco = eventos[:4] + eventos[5:]
        self.assertEqual(self.escribir(con_hueco, documentos), 1)

        reescritos, previo = json.loads(json.dumps(eventos)), contrato.CEROS
        reescritos[2]["resultado"] = "denegado"
        for evento in reescritos:
            evento["hash_previo"] = previo
            evento["hash"] = previo = contrato.hash_de_evento(evento)
        self.assertEqual(self.escribir(reescritos, documentos), 3)

        ajena = Ed25519PrivateKey.generate()
        con_otra_llave = {**documentos, 5: puntos.documento(ajena, 5, eventos[4]["hash"], "2099-01-01T00:00:00.000000Z")}
        self.assertEqual(self.escribir(eventos, con_otra_llave), 2)

        self.assertEqual(self.escribir(eventos, documentos, crudo=b"{no es json\n"), 4)

        self.assertEqual(self.escribir(eventos, {5: documentos[5]}), 5)

    def test_clave_publica_en_lugar_de_huella(self):
        eventos, documentos = cadena(5, self.llave)
        self.escribir(eventos, documentos)
        publica = base64.b64encode(claves.clave_publica_cruda(self.llave)).decode("ascii")
        codigo = verify_bitacora.main(["--eventos", str(self.carpeta / "eventos.jsonl"), "--puntos",
                                       str(self.carpeta), "--clave-publica", publica, "--cada", "5"])
        self.assertEqual(codigo, 0)
