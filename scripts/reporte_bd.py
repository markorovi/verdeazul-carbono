#!/usr/bin/env python3
"""Reporte de solo lectura de la configuración de seguridad de la base de DATABASE_URL.

Sirve para dev y para producción. Abre una transacción de solo lectura que siempre se revierte;
no imprime la cadena de conexión ni el host. Código de salida 1 si hay algún [FALLO].

Uso:
    . .\\scripts\\entorno_dev.ps1
    python scripts/reporte_bd.py
"""

from __future__ import annotations

import os
import re
import sys
from urllib.parse import parse_qs, urlsplit

import psycopg

ROLES_PROPIOS = ("app_rw", "migrador", "bit_rw")
ATRIBUTOS_ELEVADOS = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")
TABLAS_POSTGIS = ("spatial_ref_sys", "geometry_columns", "geography_columns")
TABLAS_RLS_OBLIGATORIA = (
    "mediciones_medicion",
    "mediciones_medicionversion",
    "mediciones_aprobacion",
    "mediciones_enmienda",
    "mediciones_certificado",
)
TABLA_SESIONES = "django_session"
PRIVILEGIOS_TABLA = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")
SSLMODES_TLS = ("require", "verify-ca", "verify-full")
DUENO_ESPERADO = "migrador"
PATRON_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+")


class Reporte:
    def __init__(self) -> None:
        self.totales = {"OK": 0, "AVISO": 0, "FALLO": 0}

    def _marca(self, estado: str, texto: str) -> None:
        self.totales[estado] += 1
        print(f"  [{estado}] {texto}")

    def ok(self, texto: str) -> None:
        self._marca("OK", texto)

    def aviso(self, texto: str) -> None:
        self._marca("AVISO", texto)

    def fallo(self, texto: str) -> None:
        self._marca("FALLO", texto)

    @staticmethod
    def dato(texto: str) -> None:
        print(f"  - {texto}")

    @staticmethod
    def seccion(texto: str) -> None:
        print(f"\n=== {texto} ===")


# --------------------------------------------------------------------------- consultas


def uno(conn: psycopg.Connection, consulta: str, parametros=None):
    fila = conn.execute(consulta, parametros).fetchone()
    return fila[0] if fila else None


def roles_existentes(conn: psycopg.Connection) -> set[str]:
    filas = conn.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (list(ROLES_PROPIOS),)).fetchall()
    return {f[0] for f in filas}


def tablas_del_proyecto(conn: psycopg.Connection) -> list[tuple[int, str, str]]:
    """(oid, nombre, dueño) de las tablas de public, sin las de PostGIS."""
    return conn.execute(
        "SELECT c.oid, c.relname, pg_get_userbyid(c.relowner)"
        "  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
        " WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> ALL(%s)"
        " ORDER BY c.relname",
        (list(TABLAS_POSTGIS),),
    ).fetchall()


def public_tiene_connect(acl: list[str] | None) -> bool:
    """Entrada de PUBLIC en el ACL: empieza con "=". Un ACL nulo implica CONNECT para PUBLIC."""
    if acl is None:
        return True
    return any(entrada.startswith("=") and "c" in entrada.split("/", 1)[0] for entrada in acl)


# --------------------------------------------------------------------------- secciones


def seccion_conexion(conn: psycopg.Connection, url: str, r: Reporte) -> None:
    r.seccion("Conexión")
    usuario, base, version = conn.execute(
        "SELECT current_user, current_database(), current_setting('server_version')"
    ).fetchone()
    postgis = uno(conn, "SELECT extversion FROM pg_extension WHERE extname = 'postgis'")
    r.dato(f"usuario actual: {usuario}")
    r.dato(f"base actual: {base}")
    r.dato(f"PostgreSQL: {version}")
    r.dato(f"PostGIS: {postgis or 'no instalado'}")
    try:
        sslmode = parse_qs(urlsplit(url).query).get("sslmode", [""])[-1]
    except ValueError:
        sslmode = ""
    if sslmode in SSLMODES_TLS:
        r.ok(f"la URL pide TLS (sslmode={sslmode})")
    else:
        r.fallo(f"la URL no pide TLS (sslmode={sslmode or 'sin indicar'})")
    if conn.pgconn.ssl_in_use:
        r.ok("la conexión usa TLS")
    else:
        r.fallo("la conexión NO usa TLS")


def seccion_roles(conn: psycopg.Connection, r: Reporte) -> None:
    r.seccion("Roles propios")
    filas = conn.execute(
        "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolcanlogin,"
        "       CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'neon_superuser')"
        "            THEN pg_has_role(rolname, 'neon_superuser', 'member') ELSE false END"
        "  FROM pg_roles WHERE rolname = ANY(%s) ORDER BY rolname",
        (list(ROLES_PROPIOS),),
    ).fetchall()
    for rol in sorted(set(ROLES_PROPIOS) - {f[0] for f in filas}):
        r.aviso(f"{rol} no existe en este clúster")
    for rol, superu, createrole, createdb, replicacion, bypass, login, neon in filas:
        r.dato(
            f"{rol}: rolsuper={superu}, rolcreaterole={createrole}, rolcreatedb={createdb},"
            f" rolreplication={replicacion}, rolbypassrls={bypass}, rolcanlogin={login}, neon_superuser={neon}"
        )
        elevados = [n for n, v in zip(ATRIBUTOS_ELEVADOS, (superu, createrole, createdb, replicacion, bypass)) if v]
        if neon:
            elevados.append("neon_superuser")
        if elevados:
            r.fallo(f"{rol} tiene privilegios elevados: {', '.join(elevados)}")
        else:
            r.ok(f"{rol} sin privilegios elevados")


def seccion_connect_publico(conn: psycopg.Connection, r: Reporte) -> None:
    r.seccion("CONNECT de PUBLIC en la base actual")
    base, acl = conn.execute(
        "SELECT datname, datacl::text[] FROM pg_database WHERE datname = current_database()"
    ).fetchone()
    if public_tiene_connect(acl):
        r.aviso(f"PUBLIC aún tiene CONNECT sobre {base} (falta REVOKE CONNECT ... FROM PUBLIC)")
    else:
        r.ok(f"PUBLIC no tiene CONNECT sobre {base}")


def seccion_esquema(conn: psycopg.Connection, roles: set[str], tablas, r: Reporte) -> None:
    r.seccion("Esquema public")
    if "app_rw" in roles:
        if uno(conn, "SELECT has_schema_privilege('app_rw', 'public', 'CREATE')"):
            r.fallo("app_rw tiene CREATE sobre el esquema public")
        else:
            r.ok("app_rw no tiene CREATE sobre el esquema public")
    if uno(conn, "SELECT has_schema_privilege('public', 'public', 'CREATE')"):
        r.fallo("PUBLIC tiene CREATE sobre el esquema public")
    else:
        r.ok("PUBLIC no tiene CREATE sobre el esquema public")
    r.dato(f"tablas del proyecto (sin PostGIS): {len(tablas)}")
    ajenas = [nombre for _, nombre, dueno in tablas if dueno != DUENO_ESPERADO]
    if ajenas:
        r.aviso(f"tablas cuyo dueño no es {DUENO_ESPERADO}: {', '.join(ajenas)}")
    elif tablas:
        r.ok(f"todas las tablas del proyecto pertenecen a {DUENO_ESPERADO}")


def seccion_rls(conn: psycopg.Connection, tablas, r: Reporte) -> None:
    r.seccion("Seguridad por filas (RLS)")
    filas = conn.execute(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,"
        "       (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)"
        "  FROM pg_class c WHERE c.oid = ANY(%s) ORDER BY c.relname",
        ([oid for oid, _, _ in tablas],),
    ).fetchall()
    estado = {nombre: (rls, force, politicas) for nombre, rls, force, politicas in filas}
    for nombre, (rls, force, politicas) in estado.items():
        if rls:
            r.dato(f"{nombre}: relrowsecurity={rls}, relforcerowsecurity={force}, políticas={politicas}")
    for nombre in TABLAS_RLS_OBLIGATORIA:
        if nombre not in estado:
            r.aviso(f"{nombre} no existe todavía (faltan migraciones)")
        elif estado[nombre][0] and estado[nombre][1]:
            r.ok(f"{nombre} con RLS activada y forzada")
        else:
            r.fallo(f"{nombre} existe sin RLS activada y forzada")


def seccion_disparadores_y_funciones(conn: psycopg.Connection, tablas, r: Reporte) -> None:
    r.seccion("Disparadores y funciones")
    for nombre, cantidad in conn.execute(
        "SELECT c.relname, count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid"
        " WHERE NOT t.tgisinternal AND c.oid = ANY(%s) GROUP BY c.relname ORDER BY c.relname",
        ([oid for oid, _, _ in tablas],),
    ).fetchall():
        r.dato(f"disparadores en {nombre}: {cantidad}")
    funciones = conn.execute(
        "SELECT p.proname, p.prosecdef, coalesce(array_to_string(p.proconfig, ','), '')"
        "  FROM pg_proc p"
        " WHERE p.pronamespace = 'public'::regnamespace"
        "   AND NOT EXISTS (SELECT 1 FROM pg_depend d"
        "                    WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')"
        " ORDER BY p.proname"
    ).fetchall()
    r.dato(f"funciones propias en public (sin las de extensiones): {len(funciones)}")
    definer = [nombre for nombre, es_definer, _ in funciones if es_definer]
    if definer:
        r.fallo(f"funciones SECURITY DEFINER: {', '.join(definer)}")
    else:
        r.ok("0 funciones SECURITY DEFINER")
    sin_ruta = [nombre for nombre, _, config in funciones if "search_path=" not in config]
    for nombre in sin_ruta:
        r.aviso(f"la función {nombre} no fija search_path")
    if funciones and not sin_ruta:
        r.ok("todas las funciones propias fijan search_path")


def seccion_privilegios(conn: psycopg.Connection, roles: set[str], tablas, r: Reporte) -> None:
    r.seccion("Privilegios de app_rw")
    if "app_rw" not in roles:
        r.aviso("app_rw no existe; no hay privilegios que revisar")
        return
    if not tablas:
        r.aviso("no hay tablas del proyecto todavía")
        return
    problemas = 0
    for oid, nombre, _ in tablas:
        de_tabla = sorted(
            {f[0] for f in conn.execute(
                "SELECT x.privilege_type FROM pg_class c, aclexplode(c.relacl) x"
                " WHERE c.oid = %s AND x.grantee = 'app_rw'::regrole",
                (oid,),
            ).fetchall()} & set(PRIVILEGIOS_TABLA),
            key=PRIVILEGIOS_TABLA.index,
        )
        columnas = [f[0] for f in conn.execute(
            "SELECT a.attname FROM pg_attribute a, aclexplode(a.attacl) x"
            " WHERE a.attrelid = %s AND NOT a.attisdropped AND x.grantee = 'app_rw'::regrole"
            "   AND x.privilege_type = 'UPDATE' ORDER BY a.attnum",
            (oid,),
        ).fetchall()]
        if not de_tabla and not columnas:
            continue
        detalle = ", ".join(de_tabla) or "ninguno"
        r.dato(f"{nombre}: tabla [{detalle}]; UPDATE por columna [{', '.join(columnas) or 'ninguna'}]")
        if nombre == TABLA_SESIONES:
            continue
        prohibidos = [p for p in ("DELETE", "TRUNCATE", "UPDATE") if p in de_tabla]
        if prohibidos:
            problemas += 1
            r.fallo(f"app_rw tiene {', '.join(prohibidos)} a nivel de tabla sobre {nombre}")
    if not problemas:
        r.ok("app_rw sin DELETE, TRUNCATE ni UPDATE de tabla (salvo django_session)")


def seccion_migraciones(conn: psycopg.Connection, r: Reporte) -> None:
    r.seccion("Migraciones")
    if uno(conn, "SELECT to_regclass('public.django_migrations')") is None:
        r.aviso("no existe django_migrations")
        return
    if not uno(conn, "SELECT has_table_privilege(current_user, 'public.django_migrations', 'SELECT')"):
        r.aviso("el usuario actual no puede leer django_migrations")
        return
    filas = conn.execute(
        "SELECT app, count(*), (array_agg(name ORDER BY applied DESC, id DESC))[1]"
        "  FROM django_migrations GROUP BY app ORDER BY app"
    ).fetchall()
    for app, cantidad, ultima in filas:
        r.dato(f"{app}: {cantidad} aplicadas; última {ultima}")
    r.ok(f"migraciones aplicadas en {len(filas)} aplicaciones")


# --------------------------------------------------------------------------- principal


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("[FALLO] Falta DATABASE_URL. Cargue antes el entorno (por ejemplo . .\\scripts\\entorno_dev.ps1).")
        return 2
    try:
        conn = psycopg.connect(url, autocommit=False, connect_timeout=15)
    except psycopg.Error as error:
        print(f"[FALLO] No se pudo conectar: {PATRON_URL.sub('[REDACTADO]', str(error))}")
        return 1
    conn.read_only = True
    r = Reporte()
    try:
        roles = roles_existentes(conn)
        tablas = tablas_del_proyecto(conn)
        seccion_conexion(conn, url, r)
        seccion_roles(conn, r)
        seccion_connect_publico(conn, r)
        seccion_esquema(conn, roles, tablas, r)
        seccion_rls(conn, tablas, r)
        seccion_disparadores_y_funciones(conn, tablas, r)
        seccion_privilegios(conn, roles, tablas, r)
        seccion_migraciones(conn, r)
    except psycopg.Error as error:
        r.fallo(f"error de consulta: {error.sqlstate} {PATRON_URL.sub('[REDACTADO]', error.diag.message_primary or '')}")
    finally:
        conn.rollback()
        conn.close()
    print(f"\nTotal: {r.totales['OK']} [OK], {r.totales['AVISO']} [AVISO], {r.totales['FALLO']} [FALLO]")
    return 1 if r.totales["FALLO"] else 0


if __name__ == "__main__":
    sys.exit(main())
