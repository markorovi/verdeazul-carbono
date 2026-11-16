#!/usr/bin/env python3
"""Pruebas de la autenticación (Argon2id + TOTP) contra la base dev, como app_rw.

Uso (en una sesión con el entorno cargado, sin switches):
    . .\\scripts\\entorno_dev.ps1
    python scripts/probar_autenticacion.py

Todo corre dentro de una transacción que siempre se revierte: no quedan cuentas ni sesiones, y al
final los conteos de usuarios, sesiones y roles asignados deben ser iguales a los iniciales.
Las cuentas propias usan el dominio autoprueba.test; las 7 cuentas de prueba del dominio por
defecto se siembran dentro de la transacción para comprobar que las pruebas conviven con ellas.
Nunca imprime contraseñas, códigos, secretos ni la salida del comando crear_cuentas_prueba.
"""

import io
import logging
import os
import re
import secrets
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Callable

if os.environ.get("ENTORNO") != "local":
    sys.exit("[FALLO] Este script solo corre con ENTORNO=local. Cargue: . .\\scripts\\entorno_dev.ps1")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402

django.setup()

from django.contrib.auth.hashers import check_password, make_password  # noqa: E402
from django.contrib.sessions.models import Session  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.db import DatabaseError, connection, transaction  # noqa: E402
from django.http import HttpRequest  # noqa: E402
from django.test import Client  # noqa: E402
from django.utils import timezone  # noqa: E402

from usuarios import autenticacion, cifrado, totp  # noqa: E402
from usuarios.management.commands.crear_cuentas_prueba import (  # noqa: E402
    DOMINIO_POR_DEFECTO,
    cuentas_para,
)
from usuarios.models import RolUsuario, Usuario  # noqa: E402
from usuarios.views import MENSAJE_FALLO  # noqa: E402

HOST = "localhost"
# Dominio exclusivo de este script; las cuentas reales de prueba usan DOMINIO_POR_DEFECTO.
DOMINIO = "autoprueba.test"
CANTIDAD_CUENTAS = len(cuentas_para(DOMINIO))
URL_ACCESO = "/acceso/"
URL_SEGUNDO_FACTOR = "/acceso/segundo-factor/"
URL_CUENTA = "/cuenta/"
URL_SALIDA = "/salida/"
MARGEN_PASO_SEGUNDOS = 3
PATRON_CSRF = re.compile(r'name="csrfmiddlewaretoken" value="[^"]*"')

# Valores sensibles usados en las pruebas; al final se comprueba que no aparezcan en el registro.
SENSIBLES: set[str] = set()


class CapturaRegistro(logging.Handler):
    def __init__(self):
        super().__init__()
        self.mensajes: list[str] = []

    def emit(self, record):
        self.mensajes.append(record.getMessage())


@dataclass
class Cuenta:
    usuario: Usuario
    contrasena: str
    secreto: str | None


# --------------------------------------------------------------------------- apoyo


def crear_cuenta(activo: bool = True, con_totp: bool = True) -> Cuenta:
    usuario_id = uuid.uuid4()
    contrasena = secrets.token_urlsafe(18)
    secreto = totp.generar_secreto() if con_totp else None
    SENSIBLES.update(v for v in (contrasena, secreto) if v)
    usuario = Usuario.objects.create(
        id=usuario_id,
        correo=f"auth-{usuario_id.hex[:12]}@{DOMINIO}",
        nombre="Cuenta de prueba de autenticación",
        activo=activo,
        password=make_password(contrasena),
        totp_secreto_cifrado=cifrado.cifrar(secreto, usuario_id) if secreto else None,
    )
    return Cuenta(usuario, contrasena, secreto)


def cliente() -> Client:
    return Client(HTTP_HOST=HOST)


def esperar_margen_de_paso() -> None:
    """Evita generar un código justo antes de que cambie el paso de 30 s."""
    restante = totp.PASO_SEGUNDOS - (time.time() % totp.PASO_SEGUNDOS)
    if restante < MARGEN_PASO_SEGUNDOS:
        time.sleep(restante + 0.2)


def codigo(cuenta: Cuenta, desfase_pasos: int = 0) -> str:
    valor = totp.codigo_para(cuenta.secreto, time.time() + desfase_pasos * totp.PASO_SEGUNDOS)
    SENSIBLES.add(valor)
    return valor


def codigo_incorrecto(cuenta: Cuenta) -> str:
    validos = {codigo(cuenta, d) for d in (-1, 0, 1)}
    candidato = int(codigo(cuenta))
    while f"{candidato:06d}" in validos:
        candidato = (candidato + 1) % 10**totp.DIGITOS
    return f"{candidato:06d}"


def paso1(c: Client, correo: str, contrasena: str):
    return c.post(URL_ACCESO, {"correo": correo, "password": contrasena})


def paso2(c: Client, valor: str):
    return c.post(URL_SEGUNDO_FACTOR, {"codigo": valor})


def iniciar_sesion(c: Client, cuenta: Cuenta, desfase_pasos: int = 0):
    paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    return paso2(c, codigo(cuenta, desfase_pasos))


def clave_sesion(c: Client) -> str | None:
    cookie = c.cookies.get("sessionid")
    return cookie.value if cookie else None


def huella(respuesta) -> tuple[int, str]:
    """Código HTTP y cuerpo sin el token CSRF (que cambia en cada respuesta)."""
    return respuesta.status_code, PATRON_CSRF.sub('name="csrfmiddlewaretoken" value=""', respuesta.content.decode())


def es_fallo_generico(respuesta) -> bool:
    return respuesta.status_code == 200 and MENSAJE_FALLO in respuesta.content.decode()


def redirige_a(respuesta, destino: str) -> bool:
    return respuesta.status_code == 302 and respuesta["Location"].startswith(destino)


def recargar(cuenta: Cuenta) -> Usuario:
    return Usuario.objects.get(pk=cuenta.usuario.pk)


# --------------------------------------------------------------------------- pruebas


def prueba_inicio_correcto():
    cuenta = crear_cuenta()
    c = cliente()
    esperar_margen_de_paso()
    r1 = paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    clave_paso1 = clave_sesion(c)
    r2 = paso2(c, codigo(cuenta))
    clave_final = clave_sesion(c)
    r3 = c.get(URL_CUENTA)
    ok = (
        redirige_a(r1, URL_SEGUNDO_FACTOR)
        and redirige_a(r2, URL_CUENTA)
        and r3.status_code == 200
        and clave_paso1 != clave_final
    )
    return ok, f"{r1.status_code}/{r2.status_code}/{r3.status_code}, clave cambia={clave_paso1 != clave_final}"


def respuestas_de_fallo_paso1():
    existente = crear_cuenta()
    inactiva = crear_cuenta(activo=False)
    sin_totp = crear_cuenta(con_totp=False)
    inexistente = f"no-existe-{uuid.uuid4().hex[:8]}@{DOMINIO}"
    SENSIBLES.add(inexistente)
    casos = {
        "contraseña incorrecta": (existente.usuario.correo, existente.contrasena + "x"),
        "usuario inexistente": (inexistente, secrets.token_urlsafe(18)),
        "usuario inactivo": (inactiva.usuario.correo, inactiva.contrasena),
        "usuario sin TOTP": (sin_totp.usuario.correo, sin_totp.contrasena),
    }
    respuestas = {}
    for nombre, (correo, contrasena) in casos.items():
        c = cliente()
        r = paso1(c, correo, contrasena)
        respuestas[nombre] = (huella(r), es_fallo_generico(r), autenticacion.CLAVE_PRE_AUTH in c.session)
    return respuestas


def prueba_fallos_identicos(respuestas, caso):
    referencia = respuestas["contraseña incorrecta"]
    huella_caso, generico, pre_auth = respuestas[caso]
    ok = generico and not pre_auth and huella_caso == referencia[0]
    return ok, f"HTTP {huella_caso[0]}, mensaje genérico={generico}, igual a referencia={huella_caso == referencia[0]}"


def prueba_codigo_incorrecto():
    cuenta = crear_cuenta()
    c = cliente()
    paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    r = paso2(c, codigo_incorrecto(cuenta))
    sesion = c.get(URL_CUENTA)
    ok = es_fallo_generico(r) and redirige_a(sesion, URL_ACCESO)
    return ok, f"HTTP {r.status_code}, genérico={es_fallo_generico(r)}, /cuenta/ {sesion.status_code}"


def prueba_reutilizacion():
    cuenta = crear_cuenta()
    c = cliente()
    esperar_margen_de_paso()
    valor = codigo(cuenta)
    paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    primero = paso2(c, valor)
    c.post(URL_SALIDA)
    paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    segundo = paso2(c, valor)
    ok = redirige_a(primero, URL_CUENTA) and es_fallo_generico(segundo)
    return ok, f"primer uso {primero.status_code}, reutilizado: genérico={es_fallo_generico(segundo)}"


def prueba_pasos_vecinos():
    cuenta = crear_cuenta()
    c = cliente()
    esperar_margen_de_paso()
    anterior = iniciar_sesion(c, cuenta, -1)
    c.post(URL_SALIDA)
    siguiente = iniciar_sesion(c, cuenta, +1)
    ok = redirige_a(anterior, URL_CUENTA) and redirige_a(siguiente, URL_CUENTA)
    return ok, f"anterior {anterior.status_code}, siguiente {siguiente.status_code}"


def prueba_pre_auth_expirado():
    cuenta = crear_cuenta()
    c = cliente()
    paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    sesion = c.session
    estado = sesion[autenticacion.CLAVE_PRE_AUTH]
    estado["expira"] = time.time() - 1
    sesion[autenticacion.CLAVE_PRE_AUTH] = estado
    sesion.save()
    r = paso2(c, codigo(cuenta))
    cuenta_r = c.get(URL_CUENTA)
    ok = redirige_a(r, URL_ACCESO) and redirige_a(cuenta_r, URL_ACCESO)
    return ok, f"paso 2 {r.status_code} a {r.get('Location', '-')}, /cuenta/ {cuenta_r.status_code}"


def prueba_paso2_sin_paso1():
    r = cliente().get(URL_SEGUNDO_FACTOR)
    return redirige_a(r, URL_ACCESO), f"{r.status_code} a {r.get('Location', '-')}"


def prueba_cuenta_sin_sesion():
    r = cliente().get(URL_CUENTA)
    return redirige_a(r, URL_ACCESO), f"{r.status_code} a {r.get('Location', '-')}"


def prueba_bloqueo_por_contrasena():
    cuenta = crear_cuenta()
    c = cliente()
    for _ in range(autenticacion.MAX_INTENTOS):
        paso1(c, cuenta.usuario.correo, cuenta.contrasena + "x")
    usuario = recargar(cuenta)
    esperar_margen_de_paso()
    r = paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    bloqueada = autenticacion.esta_bloqueado(usuario)
    ok = usuario.intentos_fallidos == autenticacion.MAX_INTENTOS and bloqueada and es_fallo_generico(r)
    return ok, f"intentos={usuario.intentos_fallidos}, bloqueada={bloqueada}, con datos correctos genérico={es_fallo_generico(r)}", cuenta


def prueba_bloqueo_por_codigo():
    cuenta = crear_cuenta()
    c = cliente()
    paso1(c, cuenta.usuario.correo, cuenta.contrasena)
    fallo = None
    for _ in range(autenticacion.MAX_INTENTOS):
        fallo = paso2(c, codigo_incorrecto(cuenta))
    esperar_margen_de_paso()
    correcto = paso2(c, codigo(cuenta))
    usuario = recargar(cuenta)
    bloqueada = autenticacion.esta_bloqueado(usuario)
    iguales = huella(fallo) == huella(correcto)
    ok = bloqueada and es_fallo_generico(correcto) and iguales
    return ok, f"bloqueada={bloqueada}, código correcto rechazado={es_fallo_generico(correcto)}, misma respuesta={iguales}"


def prueba_desbloqueo_y_contador(cuenta: Cuenta):
    Usuario.objects.filter(pk=cuenta.usuario.pk).update(
        bloqueado_hasta=timezone.now() - timedelta(seconds=1)
    )
    c = cliente()
    esperar_margen_de_paso()
    r = iniciar_sesion(c, cuenta)
    usuario = recargar(cuenta)
    ok = redirige_a(r, URL_CUENTA) and usuario.intentos_fallidos == 0 and usuario.totp_confirmado
    return ok, f"{r.status_code}, intentos={usuario.intentos_fallidos}, totp_confirmado={usuario.totp_confirmado}"


def prueba_salida():
    cuenta = crear_cuenta()
    c = cliente()
    esperar_margen_de_paso()
    iniciar_sesion(c, cuenta)
    clave = clave_sesion(c)
    por_get = c.get(URL_SALIDA)
    sigue = c.get(URL_CUENTA).status_code == 200
    por_post = c.post(URL_SALIDA)
    fila = Session.objects.filter(session_key=clave).exists()
    despues = c.get(URL_CUENTA)
    ok = por_get.status_code == 405 and sigue and redirige_a(por_post, URL_ACCESO) and not fila and redirige_a(despues, URL_ACCESO)
    return ok, f"GET {por_get.status_code} (sesión sigue={sigue}), POST {por_post.status_code}, fila de sesión={fila}"


def prueba_secreto_cifrado():
    cuenta = crear_cuenta()
    with connection.cursor() as cursor:
        cursor.execute("SELECT totp_secreto_cifrado FROM usuarios_usuario WHERE id = %s", [cuenta.usuario.pk])
        blob = bytes(cursor.fetchone()[0])
    en_claro = cuenta.secreto.encode("ascii") in blob or totp._bytes_del_secreto(cuenta.secreto) in blob
    descifra = cifrado.descifrar(blob, cuenta.usuario.pk) == cuenta.secreto
    return (not en_claro) and descifra, f"secreto visible en la columna={en_claro}, descifra al original={descifra}"


def prueba_cookie_sesion():
    cuenta = crear_cuenta()
    c = cliente()
    esperar_margen_de_paso()
    r = iniciar_sesion(c, cuenta)
    morsel = r.cookies.get("sessionid")
    httponly = bool(morsel and morsel["httponly"])
    samesite = morsel["samesite"] if morsel else "-"
    return httponly and samesite == "Strict", f"HttpOnly={httponly}, SameSite={samesite}"


def prueba_mfa_reciente():
    cuenta = crear_cuenta()
    c = cliente()
    esperar_margen_de_paso()
    iniciar_sesion(c, cuenta)
    request = HttpRequest()
    request.session = c.session
    reciente = autenticacion.mfa_reciente(request, 60)
    request.session[autenticacion.CLAVE_MFA] = time.time() - 1000
    vencido = autenticacion.mfa_reciente(request, 300)
    return reciente and not vencido, f"recién hecho={reciente}, hace 1000 s con límite 300={vencido}"


def ejecutar_sql(sql: str, parametros) -> str:
    try:
        with transaction.atomic():
            with connection.cursor() as cursor:
                cursor.execute(sql, parametros)
        return "pasa"
    except DatabaseError as error:
        return f"falla {getattr(error.__cause__, 'sqlstate', '?')}"


def prueba_columnas_app_rw():
    cuenta = crear_cuenta()
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_user")
        rol = cursor.fetchone()[0]
    nuevas = ejecutar_sql(
        "UPDATE usuarios_usuario SET totp_secreto_cifrado = totp_secreto_cifrado, totp_confirmado = %s,"
        " totp_ultimo_paso = %s, intentos_fallidos = %s, bloqueado_hasta = NULL WHERE id = %s",
        [False, 1, 0, cuenta.usuario.pk],
    )
    correo = ejecutar_sql(
        "UPDATE usuarios_usuario SET correo = %s WHERE id = %s", [f"otro@{DOMINIO}", cuenta.usuario.pk]
    )
    otra_tabla = ejecutar_sql("UPDATE usuarios_rol SET nombre = nombre WHERE codigo = %s", ["R1"])
    ok = rol == "app_rw" and nuevas == "pasa" and correo == "falla 42501" and otra_tabla == "falla 42501"
    return ok, f"rol={rol}; columnas nuevas {nuevas}; correo {correo}; usuarios_rol {otra_tabla}"


def ejecutar_comando(dominio: str) -> str:
    """Ejecuta crear_cuentas_prueba y devuelve su salida en memoria (nunca se imprime)."""
    salida = io.StringIO()
    call_command("crear_cuentas_prueba", dominio=dominio, stdout=salida)
    texto = salida.getvalue()
    salida.close()
    return texto


def filas_de_credenciales(salida: str) -> list[tuple[str, str, str]]:
    """(correo, contraseña, secreto) de cada fila de la salida; los valores se marcan como sensibles."""
    filas = []
    for linea in salida.splitlines():
        if "otpauth://" not in linea:
            continue
        correo, _, contrasena, secreto, _ = (parte.strip() for parte in linea.split(" | "))
        SENSIBLES.update((contrasena, secreto))
        filas.append((correo, contrasena, secreto))
    return filas


def cuentas_del_comando(dominio: str) -> dict[str, list[str]]:
    correos = [correo for correo, _ in cuentas_para(dominio)]
    vigentes = {}
    for asignacion in RolUsuario.objects.filter(usuario__correo__in=correos, hasta__isnull=True):
        vigentes.setdefault(asignacion.usuario_id, []).append(asignacion.rol_id)
    return {u.correo: vigentes.get(u.pk, []) for u in Usuario.objects.filter(correo__in=correos)}


def credenciales_validas(filas: list[tuple[str, str, str]]) -> bool:
    """Comprueba en memoria que cada fila corresponde a su cuenta. No imprime nada."""
    for correo, contrasena, secreto in filas:
        usuario = Usuario.objects.get(correo=correo)
        if not check_password(contrasena, usuario.password):
            return False
        if cifrado.descifrar(usuario.totp_secreto_cifrado, usuario.pk) != secreto:
            return False
    return True


def prueba_comando():
    previas = cuentas_del_comando(DOMINIO)
    filas = filas_de_credenciales(ejecutar_comando(DOMINIO))
    creadas = cuentas_del_comando(DOMINIO)
    un_rol_cada_una = all(creadas.get(correo) == [rol] for correo, rol in cuentas_para(DOMINIO))
    nuevas_esperadas = CANTIDAD_CUENTAS - len(previas)
    validas = credenciales_validas(filas)
    segunda = ejecutar_comando(DOMINIO)
    sin_cambios = cuentas_del_comando(DOMINIO) == creadas
    ya_existen = sum("ya existe" in linea for linea in segunda.splitlines())
    ok = (
        len(creadas) == CANTIDAD_CUENTAS
        and un_rol_cada_una
        and len(filas) == nuevas_esperadas
        and validas
        and sin_cambios
        and ya_existen == CANTIDAD_CUENTAS
    )
    return ok, (
        f"previas={len(previas)}, cuentas={len(creadas)}, un rol vigente cada una={un_rol_cada_una},"
        f" filas={len(filas)}, credenciales válidas={validas}, 2.a ejecución sin cambios={sin_cambios}"
    )


def estado_de_cuentas(dominio: str) -> dict[str, tuple]:
    """Intentos fallidos y bloqueo de cada cuenta de prueba del dominio."""
    correos = [correo for correo, _ in cuentas_para(dominio)]
    return {
        u.correo: (u.intentos_fallidos, u.bloqueado_hasta)
        for u in Usuario.objects.filter(correo__in=correos)
    }


def sembrar_cuentas_existentes() -> dict[str, tuple]:
    """Siembra (o encuentra) las 7 cuentas del dominio por defecto y guarda su estado."""
    filas_de_credenciales(ejecutar_comando(DOMINIO_POR_DEFECTO))
    return estado_de_cuentas(DOMINIO_POR_DEFECTO)


def prueba_convivencia(estado_inicial: dict[str, tuple]):
    estado_final = estado_de_cuentas(DOMINIO_POR_DEFECTO)
    existen = len(estado_final) == CANTIDAD_CUENTAS
    intactas = estado_final == estado_inicial
    return existen and intactas, f"cuentas sembradas={len(estado_final)}, sin alterar={intactas}"


# --------------------------------------------------------------------------- ejecución


@dataclass(frozen=True)
class Resultado:
    id: str
    descripcion: str
    esperado: str
    obtenido: str
    ok: bool


def correr(id_: str, descripcion: str, esperado: str, funcion: Callable) -> Resultado:
    try:
        with transaction.atomic():
            ok, obtenido = funcion()[:2]
    except Exception as error:  # cualquier error es un fallo de la prueba, sin detalles sensibles
        return Resultado(id_, descripcion, esperado, f"excepción {type(error).__name__}", False)
    return Resultado(id_, descripcion, esperado, obtenido, ok)


def ejecutar_pruebas(captura: CapturaRegistro) -> list[Resultado]:
    try:
        with transaction.atomic():
            estado_sembrado = sembrar_cuentas_existentes()
    except Exception:  # T22 quedará en FALLA
        estado_sembrado = None
    resultados = [
        correr("T01", "Contraseña y código correctos inician sesión; la clave de sesión cambia",
               "302/302/200, clave cambia", prueba_inicio_correcto),
    ]
    try:
        with transaction.atomic():
            fallos = respuestas_de_fallo_paso1()
    except Exception:  # las pruebas T02 a T05 quedarán en FALLA
        fallos = {}
    for numero, caso in enumerate(["usuario inexistente", "usuario inactivo", "usuario sin TOTP"], start=2):
        resultados.append(
            correr(f"T{numero:02d}", f"Paso 1 con {caso}: misma respuesta que contraseña incorrecta",
                   "HTTP 200, mensaje genérico, idéntica", lambda caso=caso: prueba_fallos_identicos(fallos, caso))
        )
    resultados.append(correr("T05", "Contraseña incorrecta: mensaje genérico sin estado intermedio",
                             "HTTP 200, genérico", lambda: prueba_fallos_identicos(fallos, "contraseña incorrecta")))
    resultados += [
        correr("T06", "Código TOTP incorrecto", "fallo genérico, sin sesión", prueba_codigo_incorrecto),
        correr("T07", "Mismo código TOTP reutilizado", "rechazado", prueba_reutilizacion),
        correr("T08", "Códigos del paso anterior y del siguiente", "ambos aceptados", prueba_pasos_vecinos),
        correr("T09", "Estado intermedio expirado", "vuelve a /acceso/", prueba_pre_auth_expirado),
        correr("T10", "Paso 2 sin paso 1", "302 a /acceso/", prueba_paso2_sin_paso1),
        correr("T11", "/cuenta/ sin sesión", "302 a /acceso/", prueba_cuenta_sin_sesion),
    ]
    bloqueada = {}

    def bloqueo_y_guardar():
        ok, obtenido, cuenta = prueba_bloqueo_por_contrasena()
        bloqueada["cuenta"] = cuenta
        return ok, obtenido

    resultados += [
        correr("T12", "5 contraseñas incorrectas bloquean incluso con datos correctos",
               "intentos=5, bloqueada, genérico", bloqueo_y_guardar),
        correr("T13", "5 códigos incorrectos bloquean y el código correcto se rechaza igual",
               "bloqueada, misma respuesta", prueba_bloqueo_por_codigo),
        correr("T14", "Pasado bloqueado_hasta, el acceso funciona y el contador vuelve a 0",
               "302, intentos=0", lambda: prueba_desbloqueo_y_contador(bloqueada["cuenta"])),
        correr("T15", "/salida/ por GET no cierra sesión; por POST sí y borra la fila",
               "GET 405, POST 302, sin fila", prueba_salida),
        correr("T16", "Secreto TOTP cifrado en la columna", "no visible, descifra", prueba_secreto_cifrado),
        correr("T17", "Cookie de sesión", "HttpOnly, SameSite=Strict", prueba_cookie_sesion),
        correr("T18", "mfa_reciente según la antigüedad del segundo factor", "True, luego False", prueba_mfa_reciente),
        correr("T19", "app_rw: columnas nuevas sí; correo y otra tabla no",
               "pasa, falla 42501, falla 42501", prueba_columnas_app_rw),
        correr("T20", "Comando crear_cuentas_prueba (salida en memoria, no se imprime)",
               "7 cuentas, 1 rol c/u, 1 fila por cuenta nueva, idempotente", prueba_comando),
    ]
    con_secretos = [m for m in captura.mensajes if any(s in m for s in SENSIBLES)]
    resultados.append(
        Resultado("T21", "El registro de eventos no contiene contraseñas, códigos, secretos ni correos inexistentes",
                  "0 mensajes con datos sensibles", f"{len(con_secretos)} de {len(captura.mensajes)}",
                  not con_secretos and len(captura.mensajes) > 0)
    )
    resultados.append(
        correr("T22", "Las pruebas conviven con cuentas existentes",
               "7 cuentas sembradas, sin alterar",
               lambda: prueba_convivencia(estado_sembrado) if estado_sembrado is not None
               else (False, "no se pudieron sembrar"))
    )
    return resultados


def imprimir_tabla(resultados: list[Resultado]) -> None:
    encabezado = ("id", "descripción", "esperado", "obtenido", "OK/FALLA")
    filas = [(r.id, r.descripcion, r.esperado, r.obtenido, "OK" if r.ok else "FALLA") for r in resultados]
    anchos = [max(len(encabezado[i]), *(len(f[i]) for f in filas)) for i in range(len(encabezado))]
    print(" | ".join(h.ljust(anchos[i]) for i, h in enumerate(encabezado)))
    print("-+-".join("-" * a for a in anchos))
    for fila in filas:
        print(" | ".join(v.ljust(anchos[i]) for i, v in enumerate(fila)))


def conteos() -> dict[str, int]:
    return {
        "usuarios": Usuario.objects.count(),
        "sesiones": Session.objects.count(),
        "rolusuario": RolUsuario.objects.count(),
    }


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    registro = logging.getLogger("verdeazul.autenticacion")
    captura = CapturaRegistro()
    registro.addHandler(captura)
    registro.propagate = False
    iniciales = conteos()
    with transaction.atomic():
        try:
            resultados = ejecutar_pruebas(captura)
        finally:
            transaction.set_rollback(True)
    imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    print(f"\nTotal: {correctas}/{len(resultados)} OK")
    finales = conteos()
    limpio = finales == iniciales
    print(f"Conteos antes: {iniciales}; después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio else 1


if __name__ == "__main__":
    sys.exit(main())
