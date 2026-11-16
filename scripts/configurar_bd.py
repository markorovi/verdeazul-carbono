#!/usr/bin/env python3
"""Configura los roles de PostgreSQL (Neon) del proyecto y guarda sus cadenas en Secret Manager.

Bases implicadas (se pide la cadena del DUEÑO de cada una):
  - negocio:  roles migrador (crea objetos en las migraciones) y app_rw (la aplicación).
  - bitácora: rol bit_rw.

Uso:
  python scripts/configurar_bd.py --entorno dev --simular   # solo muestra el plan
  python scripts/configurar_bd.py --entorno dev             # ejecuta (pide las cadenas sin eco)

Reglas:
  - Nunca imprime ni guarda en disco cadenas de conexión ni contraseñas.
  - Las contraseñas nuevas solo existen en memoria y llegan a Secret Manager por stdin.
  - Todo SQL con identificadores o valores se compone con psycopg.sql.
  - Los roles se crean con SQL (no desde el panel de Neon): así no son miembros de
    neon_superuser y no pueden saltarse RLS.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit, urlunsplit

import psycopg
from psycopg import sql

ROLES_NEGOCIO = ("migrador", "app_rw")
ROL_BITACORA = "bit_rw"
ATRIBUTOS_TEXTO = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
ATRIBUTOS_ROL = sql.SQL(ATRIBUTOS_TEXTO)
TABLAS_POSTGIS = ("spatial_ref_sys", "geometry_columns", "geography_columns")
ESQUEMAS_URL = ("postgresql", "postgres")
SSLMODES_ACEPTADOS = ("require", "verify-ca", "verify-full")
TIEMPO_CONEXION = 15
REINTENTOS_CONEXION = 3

SECRETOS = {
    "dev": {
        "app": "DEV_DATABASE_URL_APP",
        "migrador": "DEV_DATABASE_URL_MIGRADOR",
        "bitacora": "DEV_DATABASE_URL_BITACORA",
    },
    "prod": {
        "app": "DATABASE_URL_APP",
        "migrador": "DATABASE_URL_MIGRADOR",
        "bitacora": "DATABASE_URL_BITACORA",
    },
}
# Rol de base de datos que corresponde a cada secreto.
ROL_DE_SECRETO = {"app": "app_rw", "migrador": "migrador", "bitacora": ROL_BITACORA}
# Secretos que la cuenta de servicio de Cloud Run puede leer (solo en prod). MIGRADOR nunca.
ACCESO_CUENTA_SERVICIO = ("app", "bitacora")

GCLOUD_RESPALDO = (
    r"C:\Users\Marco Rodríguez\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
)

MARCAS = {"ok": "✔", "aviso": "⚠", "fallo": "✘"}


# --------------------------------------------------------------------------- redacción

_SENSIBLES: set[str] = set()
# Cualquier URL con esquema (incluidas las de conexión) se oculta en los mensajes.
_PATRON_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")


def registrar_sensible(*valores: str | None) -> None:
    """Anota valores que nunca deben aparecer en pantalla (cadenas, contraseñas)."""
    for valor in valores:
        if valor:
            _SENSIBLES.add(valor)
            _SENSIBLES.add(quote(valor, safe=""))


def redactar(texto: object) -> str:
    """Sustituye por [REDACTADO] cualquier valor sensible conocido y cualquier URL."""
    texto = str(texto)
    for valor in sorted(_SENSIBLES, key=len, reverse=True):
        texto = texto.replace(valor, "[REDACTADO]")
    return _PATRON_URL.sub("[REDACTADO]", texto)


class Abortar(Exception):
    """Error controlado: se muestra (redactado) y el script termina con código 1."""


# --------------------------------------------------------------------------- salida


class Resumen:
    def __init__(self) -> None:
        self.pasos: list[tuple[str, str]] = []

    def _anotar(self, estado: str, texto: str) -> None:
        texto = redactar(texto)
        self.pasos.append((estado, texto))
        print(f"  {MARCAS[estado]} {texto}")

    def ok(self, texto: str) -> None:
        self._anotar("ok", texto)

    def aviso(self, texto: str) -> None:
        self._anotar("aviso", texto)

    def fallo(self, texto: str) -> None:
        self._anotar("fallo", texto)

    @property
    def hay_fallos(self) -> bool:
        return any(estado == "fallo" for estado, _ in self.pasos)

    def imprimir(self) -> None:
        titulo("RESUMEN")
        for estado, texto in self.pasos:
            print(f"  {MARCAS[estado]} {texto}")
        total = {e: sum(1 for s, _ in self.pasos if s == e) for e in MARCAS}
        print(
            f"\n  {total['ok']} correctos, {total['aviso']} avisos, {total['fallo']} fallos."
        )


def titulo(texto: str) -> None:
    print(f"\n=== {texto} ===")


def configurar_salida() -> None:
    # Evita que un símbolo (✔/✘) no representable en la consola haga fallar el script.
    for flujo in (sys.stdout, sys.stderr):
        try:
            flujo.reconfigure(errors="replace")
        except AttributeError:
            pass


def imprimir_tabla(encabezado: tuple[str, ...], filas: list[tuple]) -> None:
    def celda(valor: object) -> str:
        if isinstance(valor, bool):
            return "true" if valor else "false"
        return str(valor)

    datos = [tuple(celda(v) for v in fila) for fila in filas]
    anchos = [
        max(len(encabezado[i]), *(len(f[i]) for f in datos)) if datos else len(encabezado[i])
        for i in range(len(encabezado))
    ]
    print("    " + " | ".join(h.ljust(anchos[i]) for i, h in enumerate(encabezado)))
    print("    " + "-+-".join("-" * a for a in anchos))
    for fila in datos:
        print("    " + " | ".join(v.ljust(anchos[i]) for i, v in enumerate(fila)))


# --------------------------------------------------------------------------- cadenas


def validar_cadena(cadena: str, etiqueta: str) -> tuple[str, str]:
    """Comprueba que la cadena es de Neon, directa (sin pooler) y con TLS.

    Devuelve (host, base). Nunca incluye la cadena en los mensajes de error.
    """
    registrar_sensible(cadena)
    try:
        partes = urlsplit(cadena)
        host = (partes.hostname or "").lower()
        _ = partes.port  # lanza ValueError si el puerto no es válido
        usuario = partes.username
        clave = partes.password
    except ValueError:
        raise Abortar(f"La cadena de {etiqueta} no es una URL válida.") from None
    if clave:
        registrar_sensible(clave, unquote(clave))

    if partes.scheme not in ESQUEMAS_URL:
        raise Abortar(f"La cadena de {etiqueta} no es una cadena de PostgreSQL.")
    if not host.endswith(".neon.tech"):
        raise Abortar(f"La cadena de {etiqueta} no es de Neon (el host debe terminar en neon.tech).")
    if "-pooler" in host:
        raise Abortar(
            f"La cadena de {etiqueta} es del pooler; use la conexión directa (host sin '-pooler')."
        )
    if not usuario or not clave:
        raise Abortar(f"La cadena de {etiqueta} no incluye usuario y contraseña.")
    base = unquote(partes.path.lstrip("/"))
    if not base or "/" in base:
        raise Abortar(f"La cadena de {etiqueta} no indica una base de datos válida.")
    sslmode = parse_qs(partes.query).get("sslmode", [""])[-1]
    if sslmode not in SSLMODES_ACEPTADOS:
        raise Abortar(f"La cadena de {etiqueta} debe incluir sslmode=require.")
    return host, base


def cadena_para_rol(cadena_dueno: str, rol: str, clave: str) -> str:
    """Misma cadena del dueño cambiando solo usuario y contraseña."""
    partes = urlsplit(cadena_dueno)
    host = partes.hostname or ""
    if ":" in host:  # IPv6
        host = f"[{host}]"
    netloc = f"{quote(rol, safe='')}:{quote(clave, safe='')}@{host}"
    if partes.port:
        netloc += f":{partes.port}"
    nueva = urlunsplit((partes.scheme, netloc, partes.path, partes.query, partes.fragment))
    registrar_sensible(nueva)
    return nueva


def conectar(cadena: str, autocommit: bool = True) -> psycopg.Connection:
    """Conecta con reintentos breves (un rol recién creado puede tardar en estar disponible)."""
    ultimo: Exception | None = None
    for intento in range(1, REINTENTOS_CONEXION + 1):
        try:
            return psycopg.connect(cadena, autocommit=autocommit, connect_timeout=TIEMPO_CONEXION)
        except psycopg.OperationalError as error:
            ultimo = error
            if intento < REINTENTOS_CONEXION:
                time.sleep(3)
    raise Abortar(f"No se pudo conectar: {redactar(ultimo)}")


# --------------------------------------------------------------------------- SQL


def existe_relacion(conn: psycopg.Connection, esquema: str, nombre: str) -> bool:
    fila = conn.execute(
        "select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace"
        " where n.nspname = %s and c.relname = %s",
        (esquema, nombre),
    ).fetchone()
    return fila is not None


def asegurar_rol(conn: psycopg.Connection, rol: str, clave: str, resumen: Resumen) -> None:
    existe = conn.execute("select 1 from pg_roles where rolname = %s", (rol,)).fetchone() is not None
    verbo = sql.SQL("ALTER ROLE") if existe else sql.SQL("CREATE ROLE")
    conn.execute(
        sql.SQL("{} {} WITH {} PASSWORD {}").format(
            verbo, sql.Identifier(rol), ATRIBUTOS_ROL, sql.Literal(clave)
        )
    )
    if existe:
        resumen.ok(f"Rol {rol} ya existía: atributos reaplicados y contraseña rotada")
    else:
        resumen.ok(f"Rol {rol} creado ({ATRIBUTOS_TEXTO})")


def info_conexion(conn: psycopg.Connection, resumen: Resumen) -> str:
    usuario, version, base = conn.execute(
        "select current_user, current_setting('server_version_num')::int / 10000,"
        " current_database()"
    ).fetchone()
    resumen.ok(f"Conectado a la base {base} como {usuario}; PostgreSQL {version}")
    return base


def conceder_connect(conn: psycopg.Connection, base: str, roles: tuple[str, ...]) -> None:
    for rol in roles:
        conn.execute(
            sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                sql.Identifier(base), sql.Identifier(rol)
            )
        )


def configurar_negocio(
    conn: psycopg.Connection, claves: dict[str, str], resumen: Resumen
) -> None:
    titulo("BASE DE NEGOCIO")
    base = info_conexion(conn, resumen)

    try:
        conn.execute("CREATE EXTENSION IF NOT EXISTS postgis")
        version = conn.execute("select postgis_version()").fetchone()[0]
        resumen.ok(f"PostGIS disponible: {version}")
    except psycopg.Error as error:
        resumen.aviso(f"PostGIS no se pudo habilitar (se continúa): {error}")

    for rol in ROLES_NEGOCIO:
        asegurar_rol(conn, rol, claves[rol], resumen)

    conceder_connect(conn, base, ROLES_NEGOCIO)
    resumen.ok(f"GRANT CONNECT ON DATABASE {base} a migrador y app_rw")

    conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    resumen.ok("REVOKE CREATE ON SCHEMA public FROM PUBLIC")

    conn.execute(
        sql.SQL("GRANT USAGE, CREATE ON SCHEMA public TO {}").format(sql.Identifier("migrador"))
    )
    resumen.ok("GRANT USAGE, CREATE ON SCHEMA public a migrador")
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier("app_rw")))
    resumen.ok("GRANT USAGE ON SCHEMA public a app_rw")

    for tabla in TABLAS_POSTGIS:
        if not existe_relacion(conn, "public", tabla):
            resumen.aviso(f"public.{tabla} no existe; no se concede SELECT")
            continue
        try:
            conn.execute(
                sql.SQL("GRANT SELECT ON TABLE {} TO {}, {}").format(
                    sql.Identifier("public", tabla),
                    sql.Identifier("migrador"),
                    sql.Identifier("app_rw"),
                )
            )
            resumen.ok(f"GRANT SELECT ON public.{tabla} a migrador y app_rw")
        except psycopg.Error as error:
            resumen.fallo(f"GRANT SELECT ON public.{tabla} falló: {error}")


def configurar_bitacora(conn: psycopg.Connection, clave: str, resumen: Resumen) -> None:
    titulo("BASE DE BITÁCORA")
    base = info_conexion(conn, resumen)
    asegurar_rol(conn, ROL_BITACORA, clave, resumen)
    conceder_connect(conn, base, (ROL_BITACORA,))
    resumen.ok(f"GRANT CONNECT ON DATABASE {base} a {ROL_BITACORA}")
    conn.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(ROL_BITACORA)))
    resumen.ok(f"GRANT USAGE ON SCHEMA public a {ROL_BITACORA}")
    conn.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    resumen.ok("REVOKE CREATE ON SCHEMA public FROM PUBLIC")


# --------------------------------------------------------------------------- verificaciones

CONSULTA_ATRIBUTOS = """
select rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin,
       case when exists (select 1 from pg_roles where rolname = 'neon_superuser')
            then pg_has_role(rolname, 'neon_superuser', 'member')
            else false end as neon_superuser
  from pg_roles
 where rolname = any(%s)
 order by rolname
"""


def verificar_atributos(
    conn: psycopg.Connection, roles: tuple[str, ...], resumen: Resumen
) -> None:
    filas = conn.execute(CONSULTA_ATRIBUTOS, (list(roles),)).fetchall()
    imprimir_tabla(
        (
            "rolname",
            "rolsuper",
            "rolbypassrls",
            "rolcreaterole",
            "rolcreatedb",
            "rolcanlogin",
            "neon_superuser",
        ),
        filas,
    )
    encontrados = {fila[0] for fila in filas}
    for rol in roles:
        if rol not in encontrados:
            resumen.fallo(f"El rol {rol} no existe")
    for rol, superu, bypass, createrole, createdb, login, neon in filas:
        if login and not any((superu, bypass, createrole, createdb, neon)):
            resumen.ok(f"{rol}: solo LOGIN; sin privilegios elevados ni neon_superuser")
        else:
            resumen.fallo(
                f"{rol}: atributos inesperados (rolsuper={superu}, rolbypassrls={bypass},"
                f" rolcreaterole={createrole}, rolcreatedb={createdb}, rolcanlogin={login},"
                f" neon_superuser={neon})"
            )


def probar_conexion_rol(cadena: str, rol: str, resumen: Resumen) -> None:
    try:
        with conectar(cadena) as conn:
            usuario = conn.execute("select current_user").fetchone()[0]
            fila = conn.execute(
                "select ssl from pg_stat_ssl where pid = pg_backend_pid()"
            ).fetchone()
            tls_cliente = bool(conn.pgconn.ssl_in_use)
    except (Abortar, psycopg.Error) as error:
        resumen.fallo(f"{rol}: no se pudo conectar ({error})")
        return

    ssl_servidor = fila[0] if fila else None
    if usuario != rol:
        resumen.fallo(f"{rol}: current_user devolvió {usuario}")
    elif not tls_cliente:
        resumen.fallo(f"{rol}: la conexión NO usa TLS")
    elif ssl_servidor:
        resumen.ok(f"{rol}: conecta como {usuario}; TLS activo (cliente) y pg_stat_ssl.ssl = true")
    else:
        resumen.aviso(
            f"{rol}: conecta como {usuario} con TLS activo en el cliente, pero"
            f" pg_stat_ssl.ssl = {ssl_servidor} (en Neon el proxy termina TLS y puede"
            " hablar con la base sin TLS en su red interna)"
        )


def probar_creacion(cadena: str, rol: str, debe_poder: bool, resumen: Resumen) -> str:
    """Intenta crear (y si debe poder, borrar) una tabla dentro de una transacción con rollback."""
    nombre = "_verificacion_" + secrets.token_hex(4)
    tabla = sql.Identifier("public", nombre)
    try:
        conn = conectar(cadena, autocommit=False)
    except Abortar as error:
        resumen.fallo(f"{rol}: no se pudo conectar para la prueba de creación ({error})")
        return nombre
    try:
        try:
            conn.execute(sql.SQL("CREATE TABLE {} (id integer)").format(tabla))
            if debe_poder:
                conn.execute(sql.SQL("DROP TABLE {}").format(tabla))
            pudo = True
        except psycopg.errors.InsufficientPrivilege:
            pudo = False
        finally:
            conn.rollback()
    except psycopg.Error as error:
        resumen.fallo(f"{rol}: error inesperado en la prueba de creación ({error})")
        return nombre
    finally:
        conn.close()

    if debe_poder and pudo:
        resumen.ok(f"{rol}: puede crear y borrar una tabla en public (transacción revertida)")
    elif debe_poder:
        resumen.fallo(f"{rol}: NO pudo crear una tabla en public y debería poder")
    elif pudo:
        resumen.fallo(f"{rol}: PUDO crear una tabla en public y NO debería (permiso indebido)")
    else:
        resumen.ok(f"{rol}: crear una tabla en public falla por permiso, como se espera")
    return nombre


# --------------------------------------------------------------------------- Secret Manager


def localizar_gcloud() -> str | None:
    for nombre in ("gcloud", "gcloud.cmd"):
        ruta = shutil.which(nombre)
        if ruta:
            return ruta
    candidatos = []
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidatos.append(
            os.path.join(local, "Google", "Cloud SDK", "google-cloud-sdk", "bin", "gcloud.cmd")
        )
    candidatos.append(GCLOUD_RESPALDO)
    for ruta in candidatos:
        if os.path.isfile(ruta):
            return ruta
    return None


def ejecutar_gcloud(
    gcloud: str, argumentos: list[str], entrada: bytes = b""
) -> tuple[int, str, str]:
    resultado = subprocess.run(
        [gcloud, *argumentos],
        input=entrada,
        capture_output=True,
        timeout=180,
        check=False,
    )
    return (
        resultado.returncode,
        resultado.stdout.decode("utf-8", "replace"),
        resultado.stderr.decode("utf-8", "replace"),
    )


def resumen_error_gcloud(stderr: str) -> str:
    lineas = [l.strip() for l in stderr.splitlines() if l.strip()]
    errores = [l for l in lineas if l.startswith("ERROR")]
    return redactar((errores or lineas or ["sin detalle"])[-1])


def guardar_secreto(
    gcloud: str, proyecto: str, nombre: str, valor: str, resumen: Resumen
) -> None:
    datos = valor.encode("utf-8")  # bytes exactos, sin salto de línea final
    codigo, _, error = ejecutar_gcloud(
        gcloud,
        ["secrets", "describe", nombre, f"--project={proyecto}", "--format=value(name)"],
    )
    if codigo == 0:
        argumentos = ["secrets", "versions", "add", nombre, "--data-file=-", f"--project={proyecto}"]
        accion = "nueva versión"
    elif "NOT_FOUND" in error:
        argumentos = [
            "secrets",
            "create",
            nombre,
            "--replication-policy=automatic",
            "--data-file=-",
            f"--project={proyecto}",
        ]
        accion = "secreto creado"
    else:
        resumen.fallo(f"{nombre}: no se pudo consultar el secreto ({resumen_error_gcloud(error)})")
        return

    codigo, salida, error = ejecutar_gcloud(gcloud, argumentos, datos)
    if codigo != 0:
        resumen.fallo(f"{nombre}: gcloud falló ({resumen_error_gcloud(error)})")
        return
    coincidencia = re.search(r"Created version \[(\d+)\]", error + salida)
    version = coincidencia.group(1) if coincidencia else "desconocida"
    resumen.ok(f"{nombre}: {accion}, versión {version}")


def conceder_acceso_secreto(
    gcloud: str, proyecto: str, nombre: str, cuenta: str, resumen: Resumen
) -> None:
    codigo, _, error = ejecutar_gcloud(
        gcloud,
        [
            "secrets",
            "add-iam-policy-binding",
            nombre,
            f"--member=serviceAccount:{cuenta}",
            "--role=roles/secretmanager.secretAccessor",
            f"--project={proyecto}",
        ],
    )
    if codigo == 0:
        resumen.ok(f"{nombre}: {cuenta} puede leerlo (secretAccessor)")
    else:
        resumen.fallo(f"{nombre}: no se pudo conceder acceso ({resumen_error_gcloud(error)})")


# --------------------------------------------------------------------------- plan


def imprimir_plan(args: argparse.Namespace) -> None:
    nombres = SECRETOS[args.entorno]
    rama = "dev" if args.entorno == "dev" else "production"
    print("SIMULACIÓN (--simular): no se piden cadenas, no hay conexiones y no se ejecuta gcloud.")
    print(f"Entorno: {args.entorno} | proyecto GCP: {args.proyecto_gcp}")
    if args.entorno == "prod":
        print("En una ejecución real se exigiría escribir PRODUCCION antes de continuar.")

    pasos = [
        (
            "Entrada",
            [
                f"Pedir sin eco la cadena del DUEÑO de la base de NEGOCIO (rama {rama} de Neon).",
                f"Pedir sin eco la cadena del DUEÑO de la base de BITÁCORA (rama {rama} de Neon).",
                "Validar ambas: host *.neon.tech, sin '-pooler', con sslmode=require,"
                " con usuario y contraseña, y en bases distintas. Si no cumplen, abortar sin mostrarlas.",
                "Localizar gcloud antes de tocar nada (si no está, abortar).",
                "Generar en memoria 3 contraseñas con secrets.token_urlsafe(32):"
                " migrador, app_rw y bit_rw.",
            ],
        ),
        (
            "Base de NEGOCIO (conexión del dueño, autocommit)",
            [
                "Mostrar current_user, la base y la versión mayor de PostgreSQL.",
                "CREATE EXTENSION IF NOT EXISTS postgis y mostrar postgis_version()"
                " (si falla: aviso y se continúa).",
                f"Roles migrador y app_rw: CREATE ROLE ... {ATRIBUTOS_TEXTO} PASSWORD"
                " (o ALTER ROLE con lo mismo y contraseña nueva si ya existen).",
                "GRANT CONNECT ON DATABASE <current_database()> TO migrador, app_rw.",
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC.",
                "GRANT USAGE, CREATE ON SCHEMA public TO migrador.",
                "GRANT USAGE ON SCHEMA public TO app_rw.",
                "GRANT SELECT ON public.spatial_ref_sys, public.geometry_columns,"
                " public.geography_columns TO migrador, app_rw (solo las que existan).",
                "Sin permisos sobre tablas de negocio (se darán por tabla en las migraciones).",
            ],
        ),
        (
            "Base de BITÁCORA (conexión del dueño, autocommit)",
            [
                "Mostrar current_user, la base y la versión mayor de PostgreSQL.",
                f"Rol bit_rw: CREATE/ALTER ROLE ... {ATRIBUTOS_TEXTO} PASSWORD.",
                "GRANT CONNECT ON DATABASE <current_database()> TO bit_rw.",
                "GRANT USAGE ON SCHEMA public TO bit_rw.",
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC.",
                "Sin permisos de tabla todavía.",
            ],
        ),
        (
            "Verificaciones (si alguna falla: no se guardan secretos y el código de salida es 1)",
            [
                "Tabla rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin,"
                " pg_has_role(rolname,'neon_superuser','member') para migrador, app_rw y bit_rw:"
                " todo false salvo rolcanlogin.",
                "Conectar como cada rol nuevo (cadena del dueño cambiando solo usuario y contraseña):"
                " select current_user; TLS activo en el cliente;"
                " select ssl from pg_stat_ssl where pid = pg_backend_pid().",
                "app_rw: CREATE TABLE en public dentro de una transacción -> DEBE FALLAR por permiso.",
                "migrador: CREATE TABLE + DROP TABLE en public dentro de una transacción con"
                " ROLLBACK -> DEBE FUNCIONAR.",
                "Confirmar con el dueño que no quedó ninguna tabla de prueba.",
            ],
        ),
        (
            f"Secret Manager (gcloud, --project={args.proyecto_gcp}; valores por stdin, sin salto final)",
            [
                f"{nombres['app']} <- cadena de app_rw (base de negocio).",
                f"{nombres['migrador']} <- cadena de migrador (base de negocio).",
                f"{nombres['bitacora']} <- cadena de bit_rw (base de bitácora).",
                "Si el secreto no existe: secrets create NOMBRE --replication-policy=automatic"
                " --data-file=-; si existe: secrets versions add NOMBRE --data-file=-.",
                "Se informa solo el nombre del secreto y el número de versión.",
            ],
        ),
    ]
    if args.entorno == "prod":
        pasos.append(
            (
                "Permisos de lectura (solo prod)",
                [
                    f"{nombres['app']}: add-iam-policy-binding roles/secretmanager.secretAccessor"
                    f" para serviceAccount:{args.cuenta_servicio}.",
                    f"{nombres['bitacora']}: lo mismo.",
                    f"{nombres['migrador']}: SIN acceso para la cuenta de servicio.",
                ],
            )
        )
    else:
        pasos.append(
            (
                "Permisos de lectura",
                ["En dev no se concede acceso a la cuenta de servicio de Cloud Run."],
            )
        )

    for numero, (seccion, acciones) in enumerate(pasos, start=1):
        print(f"\n{numero}. {seccion}")
        for accion in acciones:
            print(f"   - {accion}")
    print("\nFin de la simulación: no se ejecutó nada.")


# --------------------------------------------------------------------------- principal


def analizar_argumentos(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crea/rota los roles migrador, app_rw y bit_rw en Neon y guarda sus cadenas"
        " en Secret Manager."
    )
    parser.add_argument("--entorno", choices=("dev", "prod"), default="dev")
    parser.add_argument(
        "--simular", action="store_true", help="solo muestra el plan; no pide ni ejecuta nada"
    )
    parser.add_argument("--proyecto-gcp", default="verdeazul-p2")
    parser.add_argument(
        "--cuenta-servicio", default="app-sa@verdeazul-p2.iam.gserviceaccount.com"
    )
    return parser.parse_args(argv)


def ejecutar(args: argparse.Namespace) -> int:
    resumen = Resumen()

    if args.entorno == "prod":
        respuesta = input("Va a modificar PRODUCCIÓN. Escriba PRODUCCION para continuar: ")
        if respuesta != "PRODUCCION":
            print("Abortado: no se escribió PRODUCCION.")
            return 1

    rama = "dev" if args.entorno == "dev" else "production"
    cadena_negocio = getpass.getpass(
        f"Cadena del DUEÑO de la base de NEGOCIO (rama {rama}; no se mostrará): "
    ).strip()
    registrar_sensible(cadena_negocio)
    cadena_bitacora = getpass.getpass(
        f"Cadena del DUEÑO de la base de BITÁCORA (rama {rama}; no se mostrará): "
    ).strip()
    registrar_sensible(cadena_bitacora)

    titulo("VALIDACIÓN DE ENTRADAS")
    host_negocio, base_negocio = validar_cadena(cadena_negocio, "negocio")
    host_bitacora, base_bitacora = validar_cadena(cadena_bitacora, "bitácora")
    if (host_negocio, base_negocio) == (host_bitacora, base_bitacora):
        raise Abortar("Las dos cadenas apuntan a la misma base; la bitácora debe ser otra base.")
    resumen.ok("Cadenas válidas: Neon, conexión directa (sin pooler) y sslmode=require")

    gcloud = localizar_gcloud()
    if not gcloud:
        raise Abortar("No se encontró gcloud; instálelo o agréguelo al PATH antes de continuar.")
    resumen.ok("gcloud localizado")

    claves = {rol: secrets.token_urlsafe(32) for rol in (*ROLES_NEGOCIO, ROL_BITACORA)}
    registrar_sensible(*claves.values())
    cadenas = {
        "app": cadena_para_rol(cadena_negocio, "app_rw", claves["app_rw"]),
        "migrador": cadena_para_rol(cadena_negocio, "migrador", claves["migrador"]),
        "bitacora": cadena_para_rol(cadena_bitacora, ROL_BITACORA, claves[ROL_BITACORA]),
    }

    try:
        with conectar(cadena_negocio) as conn_negocio, conectar(cadena_bitacora) as conn_bitacora:
            configurar_negocio(conn_negocio, claves, resumen)
            configurar_bitacora(conn_bitacora, claves[ROL_BITACORA], resumen)

            titulo("VERIFICACIONES")
            verificar_atributos(conn_negocio, ROLES_NEGOCIO, resumen)
            verificar_atributos(conn_bitacora, (ROL_BITACORA,), resumen)
            for clave_secreto, rol in ROL_DE_SECRETO.items():
                probar_conexion_rol(cadenas[clave_secreto], rol, resumen)
            tablas_prueba = [
                probar_creacion(cadenas["app"], "app_rw", debe_poder=False, resumen=resumen),
                probar_creacion(cadenas["migrador"], "migrador", debe_poder=True, resumen=resumen),
            ]
            restos = [t for t in tablas_prueba if existe_relacion(conn_negocio, "public", t)]
            if restos:
                resumen.fallo(f"Quedaron tablas de prueba: {', '.join(restos)}")
            else:
                resumen.ok("No quedó ninguna tabla de prueba")
    except psycopg.Error as error:
        resumen.fallo(f"Error de base de datos: {type(error).__name__}: {error}")

    if resumen.hay_fallos:
        print("\nHay fallos: NO se guardó ningún secreto.")
        resumen.imprimir()
        return 1

    titulo("SECRET MANAGER")
    nombres = SECRETOS[args.entorno]
    for clave_secreto, nombre in nombres.items():
        guardar_secreto(gcloud, args.proyecto_gcp, nombre, cadenas[clave_secreto], resumen)
    if args.entorno == "prod":
        for clave_secreto in ACCESO_CUENTA_SERVICIO:
            conceder_acceso_secreto(
                gcloud, args.proyecto_gcp, nombres[clave_secreto], args.cuenta_servicio, resumen
            )
        resumen.ok(f"{nombres['migrador']}: sin acceso para la cuenta de servicio (a propósito)")

    resumen.imprimir()
    return 1 if resumen.hay_fallos else 0


def main(argv: list[str] | None = None) -> int:
    configurar_salida()
    args = analizar_argumentos(argv)
    if args.simular:
        imprimir_plan(args)
        return 0
    try:
        return ejecutar(args)
    except Abortar as error:
        print(f"\n✘ Abortado: {redactar(error)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n✘ Cancelado por el usuario.", file=sys.stderr)
        return 130
    except Exception as error:  # nunca mostrar trazas que puedan contener cadenas
        print(f"\n✘ Error inesperado: {redactar(f'{type(error).__name__}: {error}')}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
