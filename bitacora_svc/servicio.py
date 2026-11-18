"""Lógica del servicio de bitácora sobre su propia base (cuenta bit_rw: solo SELECT e INSERT).

La cadena se serializa con pg_advisory_xact_lock: dentro del lock se lee el último evento, se toma
el sello del reloj de la base (clock_timestamp) y se comprueba que no retroceda, y el servicio
calcula seq, sello, hash_previo y hash. Lo que el cliente envíe en esos campos se descarta antes.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from psycopg import sql

from bitacora_svc import almacen as almacenes
from bitacora_svc import claves, puntos
from bitacora_svc.contrato import CEROS, calcular_hash, canonico, clase_de, formatear_sello, seudonimo
from bitacora_svc.esquema import ESQUEMA_POR_DEFECTO, validar_nombre

PUNTO_CADA_POR_DEFECTO = 25
LIMITE_MAXIMO = 500
TIEMPO_CONEXION = 10
MAX_CONEXIONES = 8
ESPERA_CONEXION = 10
INACTIVIDAD_MAXIMA = 60

COD_INTEGRA = 0
COD_CADENA = 1
COD_FIRMA = 2
COD_PUNTO = 3
COD_FORMATO = 4
COD_FALTAN_PUNTOS = 5

registro = logging.getLogger("bitacora_svc")


class RelojRetrocede(Exception):
    """El reloj de la base quedó detrás del último sello: no se anexa."""


@dataclass
class Configuracion:
    url_base: str = field(repr=False)
    sal: bytes = field(repr=False)
    llave: Ed25519PrivateKey = field(repr=False)
    almacen: object
    esquema: str = ESQUEMA_POR_DEFECTO
    punto_cada: int = PUNTO_CADA_POR_DEFECTO

    @classmethod
    def desde_entorno(cls) -> Configuracion:
        url = os.environ.get("BITACORA_DATABASE_URL") or os.environ.get("DATABASE_URL_BITACORA")
        if not url:
            raise claves.LlaveNoConfigurada("Falta BITACORA_DATABASE_URL.")
        return cls(
            url_base=url,
            sal=claves.cargar_sal(os.environ.get(claves.VARIABLE_SAL)),
            llave=claves.cargar_llave(os.environ.get(claves.VARIABLE_FIRMA)),
            # Sin valores por defecto: un almacén mal configurado no debe caer en un directorio común.
            almacen=almacenes.almacen_de(os.environ.get("BITACORA_WORM", ""), os.environ.get("BITACORA_WORM_DESTINO", "")),
            esquema=validar_nombre(os.environ.get("BITACORA_ESQUEMA", ESQUEMA_POR_DEFECTO)),
            punto_cada=int(os.environ.get("BITACORA_PUNTO_CADA", PUNTO_CADA_POR_DEFECTO)),
        )


def _log(evento: str, **datos) -> None:
    """Registro estructurado sin cuerpos de eventos ni identificadores de personas."""
    registro.info(json.dumps({"evento": evento, **datos}, sort_keys=True))


class _Conexiones:
    """Conexiones reutilizables y acotadas a la base de la bitácora.

    Abrir una conexión TLS por petición agrega latencia, y con llamadas concurrentes acumula
    conexiones esperando el lock de la cadena. El cupo limita las conexiones abiertas y las que
    quedan inactivas demasiado tiempo se descartan (el proveedor puede cerrarlas).
    """

    def __init__(self, url: str, maximo: int = MAX_CONEXIONES):
        self._url = url
        self._libres: queue.LifoQueue = queue.LifoQueue()
        self._cupos = threading.BoundedSemaphore(maximo)

    def _tomar(self) -> psycopg.Connection:
        while True:
            try:
                conexion, devuelta = self._libres.get_nowait()
            except queue.Empty:
                return psycopg.connect(self._url, connect_timeout=TIEMPO_CONEXION, autocommit=False)
            if conexion.closed or conexion.broken or time.monotonic() - devuelta > INACTIVIDAD_MAXIMA:
                conexion.close()
                continue
            return conexion

    @contextmanager
    def conexion(self):
        if not self._cupos.acquire(timeout=ESPERA_CONEXION):
            raise psycopg.OperationalError("sin conexiones disponibles")
        conexion = None
        try:
            conexion = self._tomar()
            yield conexion
            conexion.commit()
            self._libres.put((conexion, time.monotonic()))
            conexion = None
        finally:
            if conexion is not None:
                try:
                    conexion.rollback()
                except Exception as error:
                    # La conexión se descarta igual; solo se anota la clase del error.
                    registro.warning("evento=rollback_fallido clase=%s", type(error).__name__)
                conexion.close()
            self._cupos.release()


class Servicio:
    def __init__(self, configuracion: Configuracion):
        self.c = configuracion
        self.esquema = sql.Identifier(validar_nombre(configuracion.esquema))
        self.huella_propia = claves.huella_publica(configuracion.llave)
        self.almacen_falla = False
        self._revisar_pendientes = True
        self._conexiones = _Conexiones(configuracion.url_base)


    def _q(self, texto: str) -> sql.Composed:
        return sql.SQL(texto).format(e=self.esquema)

    # ----------------------------------------------------------------------- anexar

    def anexar(self, evento: dict) -> tuple[int, str]:
        evento = dict(evento)
        clase = clase_de(evento)
        identificador = evento.pop("usuario_id", None)
        # Una cuenta como objeto también es una persona: su identificador se seudonimiza igual.
        if evento.get("objeto_tipo") == "cuenta" and evento.get("objeto_id"):
            evento["objeto_id"] = seudonimo(self.c.sal, evento["objeto_id"])
        with self._conexiones.conexion() as conexion:
            conexion.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", [f"{self.c.esquema}.evento"])
            # Último evento y reloj de la base en una sola ida y vuelta, ya dentro del lock.
            ultimo_seq, ultimo_hash, ultimo_sello, ahora = conexion.execute(self._q(
                "SELECT u.seq, u.hash, u.sello, clock_timestamp() FROM (SELECT 1) AS x"
                " LEFT JOIN LATERAL (SELECT seq, hash, sello FROM {e}.evento ORDER BY seq DESC LIMIT 1) AS u ON true"
            )).fetchone()
            if ultimo_sello is not None and ahora < ultimo_sello:
                raise RelojRetrocede()
            seq = (ultimo_seq or 0) + 1
            previo = ultimo_hash or CEROS
            cuerpo = {**evento, "seq": seq, "sello": formatear_sello(ahora), "clase": clase}
            if identificador:
                cuerpo["usuario"] = seudonimo(self.c.sal, identificador)
            texto = canonico(cuerpo)
            hash_evento = calcular_hash(previo, texto)
            conexion.execute(
                self._q(
                    "INSERT INTO {e}.evento (seq, sello, clase, usuario, objeto_tipo, objeto_id, cuerpo, hash_previo, hash)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
                ),
                [seq, ahora, clase, cuerpo.get("usuario"), cuerpo.get("objeto_tipo"), cuerpo.get("objeto_id"),
                 texto.decode("utf-8"), previo, hash_evento],
            )
        _log("anexado", seq=seq, clase=clase)
        # Los pendientes solo se buscan en un múltiplo, después de una falla del almacén o en el
        # primer anexo del proceso (por si otro proceso dejó alguno pendiente).
        if seq % self.c.punto_cada == 0 or self.almacen_falla or self._revisar_pendientes:
            self._revisar_pendientes = False
            self._puntos_pendientes(seq)
        return seq, hash_evento

    # ----------------------------------------------------------------------- puntos de control

    def _puntos_pendientes(self, ultimo_seq: int) -> None:
        """Crea los puntos que falten hasta el último múltiplo; si el almacén falla, el evento ya
        está anexado y el próximo anexo reintenta."""
        esperado = ultimo_seq - ultimo_seq % self.c.punto_cada
        if esperado <= 0:
            return
        with self._conexiones.conexion() as conexion:
            faltan = [f[0] for f in conexion.execute(
                self._q("SELECT g FROM generate_series(%s::bigint, %s::bigint, %s::bigint) AS g"
                        " WHERE NOT EXISTS (SELECT 1 FROM {e}.punto p WHERE p.seq = g) ORDER BY g"),
                [self.c.punto_cada, esperado, self.c.punto_cada],
            ).fetchall()]
        try:
            for seq in faltan:
                self.crear_punto(seq)
            self.almacen_falla = False
        except almacenes.AlmacenNoDisponible as error:
            self.almacen_falla = True
            _log("punto_pendiente", motivo=str(error))

    def crear_punto(self, seq: int | None = None) -> tuple[dict, bool]:
        with self._conexiones.conexion() as conexion:
            if seq is None:
                fila = conexion.execute(self._q("SELECT max(seq) FROM {e}.evento")).fetchone()
                seq = fila[0]
                if seq is None:
                    raise ValueError("no hay eventos")
            existente = conexion.execute(self._q("SELECT documento FROM {e}.punto WHERE seq = %s"), [seq]).fetchone()
            if existente:
                return json.loads(existente[0]), False
            fila = conexion.execute(self._q("SELECT hash FROM {e}.evento WHERE seq = %s"), [seq]).fetchone()
            if fila is None:
                raise ValueError("seq inexistente")
            hash_evento = fila[0]
            fecha = formatear_sello(conexion.execute("SELECT clock_timestamp()").fetchone()[0])
        documento = puntos.documento(self.c.llave, seq, hash_evento, fecha)
        creado = True
        try:
            self.c.almacen.guardar(seq, canonico(documento))
        except almacenes.YaExiste:
            # Un intento anterior lo guardó en el almacén pero no llegó a registrarlo en la base.
            previo = puntos.leer(self.c.almacen.leer(seq) or b"{}")
            carga = previo["payload"]
            if carga.get("seq") != seq or carga.get("hash") != hash_evento or not puntos.firma_valida(previo, self.huella_propia):
                raise almacenes.AlmacenNoDisponible("el punto existente no coincide con la cadena") from None
            documento, creado = previo, False
        with self._conexiones.conexion() as conexion:
            conexion.execute(
                self._q("INSERT INTO {e}.punto (seq, hash, fecha, key_id, documento) VALUES (%s, %s, %s, %s, %s)"
                        " ON CONFLICT (seq) DO NOTHING"),
                [seq, hash_evento, documento["payload"]["fecha"], documento["payload"]["key_id"],
                 canonico(documento).decode("utf-8")],
            )
        _log("punto", seq=seq, creado=creado)
        return documento, creado

    def puntos(self) -> list[dict]:
        with self._conexiones.conexion() as conexion:
            return [json.loads(f[0]) for f in conexion.execute(self._q("SELECT documento FROM {e}.punto ORDER BY seq"))]

    # ----------------------------------------------------------------------- consultas

    def _evento_completo(self, cuerpo: str, hash_previo: str, hash_evento: str) -> dict:
        return {**json.loads(cuerpo), "hash_previo": hash_previo, "hash": hash_evento}

    def consultar(self, filtros: dict) -> list[dict]:
        condiciones, valores = [], []
        if filtros.get("usuario_id"):
            condiciones.append("usuario = %s")
            valores.append(seudonimo(self.c.sal, filtros["usuario_id"]))
        for campo in ("objeto_tipo", "objeto_id"):
            if filtros.get(campo):
                valor = filtros[campo]
                if campo == "objeto_id" and filtros.get("objeto_tipo") == "cuenta":
                    valor = seudonimo(self.c.sal, valor)
                condiciones.append(f"{campo} = %s")
                valores.append(valor)
        if filtros.get("clases"):
            condiciones.append("clase = ANY(%s)")
            valores.append(list(filtros["clases"]))
        if filtros.get("desde") is not None:
            condiciones.append("seq >= %s")
            valores.append(int(filtros["desde"]))
        if filtros.get("hasta") is not None:
            condiciones.append("seq <= %s")
            valores.append(int(filtros["hasta"]))
        limite = min(int(filtros.get("limite") or 100), LIMITE_MAXIMO)
        orden = "DESC" if filtros.get("orden") == "desc" else "ASC"
        donde = (" WHERE " + " AND ".join(condiciones)) if condiciones else ""
        # Bandit B608 aceptado: el esquema es un sql.Identifier validado, las columnas salen de una lista fija, el
        # orden de dos valores fijos y todo valor viaja como parámetro.
        consulta = self._q("SELECT cuerpo, hash_previo, hash FROM {e}.evento" + donde + f" ORDER BY seq {orden} LIMIT %s")  # nosec B608
        with self._conexiones.conexion() as conexion:
            filas = conexion.execute(consulta, [*valores, limite]).fetchall()
        return [self._evento_completo(*f) for f in filas]

    def exportar(self, desde: int = 1, hasta: int | None = None):
        consulta = "SELECT cuerpo, hash_previo, hash FROM {e}.evento WHERE seq >= %s"
        valores: list = [desde]
        if hasta is not None:
            consulta += " AND seq <= %s"
            valores.append(hasta)
        with self._conexiones.conexion() as conexion:
            filas = conexion.execute(self._q(consulta + " ORDER BY seq"), valores).fetchall()
        for fila in filas:
            yield canonico(self._evento_completo(*fila)) + b"\n"

    # ----------------------------------------------------------------------- verificación y salud

    def verificar(self) -> dict:
        with self._conexiones.conexion() as conexion:
            filas = conexion.execute(self._q("SELECT seq, cuerpo, hash_previo, hash FROM {e}.evento ORDER BY seq")).fetchall()
        resumen = {"integra": False, "eventos": len(filas), "puntos": 0}
        hashes, previo = {}, CEROS
        for esperado, (seq, cuerpo, hash_previo, hash_evento) in enumerate(filas, start=1):
            try:
                datos = json.loads(cuerpo)
            except ValueError:
                return {**resumen, "codigo": COD_FORMATO, "detalle": f"evento {seq} con formato inválido"}
            if (seq != esperado or datos.get("seq") != seq or hash_previo != previo
                    or calcular_hash(hash_previo, cuerpo.encode("utf-8")) != hash_evento):
                return {**resumen, "codigo": COD_CADENA, "detalle": f"cadena rota en el evento {seq}"}
            hashes[seq], previo = hash_evento, hash_evento
        try:
            guardados = self.c.almacen.listar()
            for seq in guardados:
                documento = puntos.leer(self.c.almacen.leer(seq) or b"{}")
                if not puntos.firma_valida(documento, self.huella_propia):
                    return {**resumen, "puntos": len(guardados), "codigo": COD_FIRMA, "detalle": f"punto {seq} con firma inválida"}
                if hashes.get(documento["payload"].get("seq")) != documento["payload"].get("hash") or documento["payload"].get("seq") != seq:
                    return {**resumen, "puntos": len(guardados), "codigo": COD_PUNTO, "detalle": f"el punto {seq} no coincide con la cadena"}
        except (almacenes.AlmacenNoDisponible, ValueError, KeyError):
            return {**resumen, "codigo": COD_FORMATO, "detalle": "no se pudieron leer los puntos"}
        resumen["puntos"] = len(guardados)
        ultimo_multiplo = len(filas) - len(filas) % self.c.punto_cada
        faltan = [s for s in range(self.c.punto_cada, ultimo_multiplo + 1, self.c.punto_cada) if s not in set(guardados)]
        if faltan:
            return {**resumen, "codigo": COD_FALTAN_PUNTOS, "detalle": f"faltan {len(faltan)} puntos esperados"}
        return {**resumen, "integra": True, "codigo": COD_INTEGRA, "detalle": "cadena y puntos íntegros"}

    def salud(self) -> dict:
        with self._conexiones.conexion() as conexion:
            ultimo = conexion.execute(self._q("SELECT coalesce(max(seq), 0) FROM {e}.evento")).fetchone()[0]
            esperado = ultimo - ultimo % self.c.punto_cada
            pendientes = conexion.execute(
                self._q("SELECT count(*) FROM generate_series(%s::bigint, %s::bigint, %s::bigint) AS g"
                        " WHERE NOT EXISTS (SELECT 1 FROM {e}.punto p WHERE p.seq = g)"),
                [self.c.punto_cada, max(esperado, 0), self.c.punto_cada],
            ).fetchone()[0] if esperado > 0 else 0
        degradado = self.almacen_falla or pendientes > 0
        return {"estado": "degradado" if degradado else "ok", "ultimo_seq": ultimo, "puntos_pendientes": pendientes}
