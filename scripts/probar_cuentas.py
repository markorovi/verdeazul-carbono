#!/usr/bin/env python3
"""Pruebas de los servicios de cuentas y roles (O6), ventanas de auditoría, acceso de emergencia y
recuperación de contraseña contra la base dev.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_cuentas.py

Corre como app_rw (DATABASE_URL_APP) a través de Django, con el patrón de probar_catalogo.py: cada
prueba en una transacción que SIEMPRE se revierte y conteos comparados al final. Las contraseñas,
los códigos de un solo uso y los secretos TOTP son sintéticos y nunca se imprimen.
"""

from __future__ import annotations

import hashlib
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import probar_catalogo as pc  # noqa: E402  (configura Django y la conexión de app_rw)

from django.contrib.auth.password_validation import CommonPasswordValidator  # noqa: E402
from django.contrib.sessions.backends.db import SessionStore  # noqa: E402
from django.contrib.sessions.models import Session  # noqa: E402
from django.db import connection  # noqa: E402

import probar_mediciones as pm  # noqa: E402
import probar_servicios as ps  # noqa: E402
from catalogo import servicios as catalogo  # noqa: E402
from mediciones import plazos  # noqa: E402
from mediciones.errores import ReglaIncumplida  # noqa: E402
from mediciones.models import Alerta  # noqa: E402
from mediciones.transaccion import hora_de_la_base  # noqa: E402
from usuarios import cifrado, codigos, totp  # noqa: E402
from usuarios import servicios as cuentas  # noqa: E402
from usuarios.models import AccesoEmergencia, CodigoUnUso, RolUsuario, Usuario  # noqa: E402

PASA = ps.PASA
condicion = ps.condicion
resultado = ps.resultado
DOMINIO = "cuentas-prueba.test"
# Valores sintéticos de prueba; ninguno corresponde a una cuenta real ni se imprime.
FRASE_LARGA = "esta es una frase de paso larga con espacios para probar la politica de contrasenas del sistema"
FRASE_NUEVA = "otra frase de paso distinta y suficientemente larga para la cuenta recuperada en la prueba"
TABLAS_CONTEO = pc.TABLAS_CONTEO + [
    "usuarios_codigounuso",
    "usuarios_ventanaauditoria",
    "usuarios_accesoemergencia",
    "django_session",
]


def en_2099(mes: int, dia: int) -> datetime:
    return datetime(2099, mes, dia, tzinfo=timezone.utc)


class Datos(pc.Datos):
    def cuenta_con_totp(self, administrador) -> tuple[Usuario, str]:
        """Cuenta dada de alta y canjeada con los servicios; devuelve la cuenta y su secreto TOTP."""
        correo = f"k-{uuid.uuid4().hex[:12]}@{DOMINIO}"
        alta = cuentas.alta_cuenta(administrador, correo, "Persona de prueba de cuentas")
        canje = cuentas.canjear_codigo(alta.codigo, correo=correo, contrasena=FRASE_LARGA)
        return Usuario.objects.get(pk=alta.usuario_id), canje.secreto_totp

    def sesion_de(self, usuario) -> str:
        sesion = SessionStore()
        sesion[cuentas.CLAVE_SESION_USUARIO] = str(usuario.pk)
        sesion.create()
        return sesion.session_key


def codigo_totp(secreto: str) -> str:
    return totp.codigo_para(secreto, time.time())


def totp_incorrecto(secreto: str) -> str:
    validos = {totp.codigo_para(secreto, time.time() + d * totp.PASO_SEGUNDOS) for d in (-1, 0, 1)}
    candidato = 0
    while f"{candidato:06d}" in validos:
        candidato += 1
    return f"{candidato:06d}"


def correo_nuevo() -> str:
    return f"k-{uuid.uuid4().hex[:12]}@{DOMINIO}"


# --------------------------------------------------------------------------- cuentas y roles


def a01():
    d = Datos()
    r4 = d.usuario("R4")
    alta = cuentas.alta_cuenta(r4, correo_nuevo(), "Cuenta nueva")
    cuenta = Usuario.objects.get(pk=alta.usuario_id)
    fila = CodigoUnUso.objects.get(usuario_id=cuenta.pk)
    ok = (cuenta.creado_por_id == r4.pk and not cuenta.has_usable_password() and not cuentas._roles_vigentes(cuenta.pk)
          and fila.proposito == "alta" and fila.huella == hashlib.sha256(alta.codigo.encode()).hexdigest()
          and fila.huella != alta.codigo and fila.vence_en - fila.emitido_en == codigos.VIGENCIA_ALTA)
    return resultado(ok, f"creado_por = actor={cuenta.creado_por_id == r4.pk}; sin contraseña ni roles; código de alta de 24 h guardado como huella")


def a02():
    d = Datos()
    r4 = d.usuario("R4")
    correo = correo_nuevo()
    alta = cuentas.alta_cuenta(r4, correo, "Cuenta nueva")
    canje = cuentas.canjear_codigo(alta.codigo, correo=correo, contrasena=FRASE_LARGA)
    cuenta = Usuario.objects.get(pk=alta.usuario_id)
    totp_ok = cifrado.descifrar(cuenta.totp_secreto_cifrado, cuenta.pk) == canje.secreto_totp
    usado = CodigoUnUso.objects.get(usuario_id=cuenta.pk).usado_en is not None
    ok = canje.proposito == "alta" and cuenta.check_password(FRASE_LARGA) and totp_ok and usado and not cuenta.totp_confirmado
    return resultado(ok, f"contraseña fijada; TOTP enrolado={totp_ok}; código usado={usado}")


def a03():
    d = Datos()
    r4, cuenta = d.usuario("R4"), d.usuario("R1")
    r = cuentas.modificar_cuenta(r4, cuenta.pk, nombre="Nombre corregido")
    nombre = Usuario.objects.filter(pk=cuenta.pk).values_list("nombre", flat=True).get()
    return resultado(nombre == "Nombre corregido" and r.roles == ("R1",), f"nombre cambiado; roles {list(r.roles)}")


def a04():
    d = Datos()
    r4, cuenta = d.usuario("R4"), d.usuario()
    r = cuentas.asignar_rol(r4, cuenta.pk, "R1")
    asignado_por = RolUsuario.objects.filter(usuario_id=cuenta.pk, rol_id="R1").values_list("asignado_por_id", flat=True).get()
    return resultado(r.roles == ("R1",) and asignado_por == r4.pk, f"roles {list(r.roles)}, asignado por el actor")


def a05():
    d = Datos()
    r4, cuenta = d.usuario("R4"), d.usuario("R1")
    obtenido = condicion(lambda: cuentas.asignar_rol(r4, cuenta.pk, "R2"))
    return resultado(obtenido == "Cd13", obtenido)


def a06():
    d = Datos()
    r4 = d.usuario("R4")
    obtenido = condicion(lambda: cuentas.asignar_rol(r4, r4.pk, "R3"))
    return resultado(obtenido == "Cd13", obtenido)


def a07():
    d = Datos()
    r4, cuenta = d.usuario("R4"), d.usuario("R2")
    obtenido = condicion(lambda: cuentas.asignar_rol(r4, cuenta.pk, "R3"))
    return resultado(obtenido == "Cd13", obtenido)


def a08():
    d = Datos()
    r4, cuenta = d.usuario("R4"), d.usuario("R3")
    obtenido = condicion(lambda: cuentas.asignar_rol(r4, cuenta.pk, "R4"))
    return resultado(obtenido == PASA, obtenido)


def a09():
    d = Datos()
    r4 = d.usuario("R4", "R3")
    obtenido = condicion(lambda: cuentas.revocar_rol(r4, r4.pk, "R3"))
    return resultado(obtenido == "Cd13", obtenido)


def a10():
    d = Datos()
    r4 = d.usuario("R4")
    cuenta, _ = d.cuenta_con_totp(r4)
    cuentas.emitir_recuperacion(d.usuario("R4"), cuenta.pk)
    propia, ajena = d.sesion_de(cuenta), d.sesion_de(r4)
    r = cuentas.dar_de_baja_cuenta(r4, cuenta.pk)
    activo = Usuario.objects.filter(pk=cuenta.pk).values_list("activo", flat=True).get()
    sesiones = set(Session.objects.filter(session_key__in=[propia, ajena]).values_list("session_key", flat=True))
    ok = not activo and r.sesiones_cerradas == 1 and r.codigos_invalidados == 1 and sesiones == {ajena}
    return resultado(ok, f"inactiva; sesiones cerradas={r.sesiones_cerradas}; códigos invalidados={r.codigos_invalidados}; otra sesión intacta={ajena in sesiones}")


def a11():
    d = Datos()
    r4 = d.usuario("R4")
    obtenido = condicion(lambda: cuentas.dar_de_baja_cuenta(r4, r4.pk))
    return resultado(obtenido == "Cd13", obtenido)


def a12():
    d = Datos()
    administrador = d.usuario("R3", "R4")
    alta = cuentas.alta_cuenta(administrador, correo_nuevo(), "Técnico nuevo")
    cuentas.asignar_rol(d.usuario("R4"), alta.usuario_id, "R1")
    ctx = d.finca()
    parcela = d.parcela(ctx)
    r = catalogo.asignar_tecnico(administrador, parcela, alta.usuario_id, hora_de_la_base() + timedelta(days=7))
    return resultado(r.prioridad == "prioritaria", f"asignación de un técnico dado de alta por el actor: {r.prioridad}")


# --------------------------------------------------------------------------- ventanas de auditoría


def ventana(d: Datos, auditor, inicio, fin, solicitante=None, abre=None) -> uuid.UUID:
    solicitante = solicitante or d.usuario("R7")
    v = cuentas.solicitar_ventana(solicitante, auditor.pk, inicio, fin).ventana_id
    if abre is not None:
        cuentas.abrir_ventana(abre, v)
    return v


def ventana_vigente(d: Datos, auditor) -> bool:
    d.actor(auditor)
    with connection.cursor() as cursor:
        cursor.execute("SELECT app_ventana_auditoria_vigente()")
        return cursor.fetchone()[0]


def w01():
    d = Datos()
    auditor = d.usuario("R5")
    ahora = hora_de_la_base()
    r = cuentas.solicitar_ventana(d.usuario("R7"), auditor.pk, ahora - timedelta(hours=1), ahora + timedelta(days=1))
    vigente = ventana_vigente(d, auditor)
    return resultado(r.estado == "solicitada" and not vigente, f"{r.estado}; da acceso antes de abrirse={vigente}")


def w02():
    d = Datos()
    auditor, solicita, abre = d.usuario("R5"), d.usuario("R7"), d.usuario("R7")
    ventana(d, auditor, en_2099(1, 1), en_2099(1, 21), solicita, abre)
    nueva = ventana(d, auditor, en_2099(2, 1), en_2099(2, 11), solicita)
    r = cuentas.abrir_ventana(abre, nueva)
    return resultado(r.estado == "abierta", f"20 días abiertos + 10 nuevos: {r.estado}")


def w03():
    d = Datos()
    obtenido = condicion(lambda: cuentas.abrir_ventana(d.usuario("R7"), uuid.uuid4()))
    return resultado(obtenido == "Cd23", obtenido)


def w04():
    d = Datos()
    auditor, solicita, abre = d.usuario("R5"), d.usuario("R7"), d.usuario("R7")
    ventana(d, auditor, en_2099(1, 1), en_2099(1, 21), solicita, abre)
    nueva = ventana(d, auditor, en_2099(2, 1), en_2099(2, 12), solicita)
    obtenido = condicion(lambda: cuentas.abrir_ventana(abre, nueva))
    return resultado(obtenido == "Cd23", f"20 + 11 días: {obtenido}")


def w05():
    d = Datos()
    tecnico = d.usuario("R1")
    obtenido = condicion(lambda: cuentas.solicitar_ventana(d.usuario("R7"), tecnico.pk, en_2099(1, 1), en_2099(1, 5)))
    return resultado(obtenido == "Cd23", obtenido)


def w06():
    d = Datos()
    solicita = d.usuario("R7")
    v = ventana(d, d.usuario("R5"), en_2099(1, 1), en_2099(1, 5), solicita)
    obtenido = condicion(lambda: cuentas.abrir_ventana(solicita, v))
    return resultado(obtenido == "Cd23", obtenido)


def w07():
    d = Datos()
    v = ventana(d, d.usuario("R5"), en_2099(1, 1), en_2099(1, 5), abre=d.usuario("R7"))
    obtenido = condicion(lambda: cuentas.abrir_ventana(d.usuario("R7"), v))
    return resultado(obtenido == "Cd23", obtenido)


def w08():
    d = Datos()
    auditor = d.usuario("R5")
    ahora = hora_de_la_base()
    ventana(d, auditor, ahora - timedelta(hours=1), ahora + timedelta(days=1), abre=d.usuario("R7"))
    vigente = ventana_vigente(d, auditor)
    return resultado(vigente, f"ventana abierta y vigente da acceso={vigente}")


# --------------------------------------------------------------------------- emergencia


def emergencia_activa(d: Datos, rol: str = "R1"):
    beneficiario, r4, r7 = d.usuario(rol), d.usuario("R4"), d.usuario("R7")
    primera = cuentas.autorizar_emergencia(r4, beneficiario.pk, rol)
    segunda = cuentas.autorizar_emergencia(r7, beneficiario.pk, rol)
    return beneficiario, r4, r7, primera, segunda


def m01():
    d = Datos()
    beneficiario, r4, r7, primera, segunda = emergencia_activa(d)
    acceso = AccesoEmergencia.objects.get(pk=segunda.acceso_id)
    avisos = list(Alerta.objects.filter(tipo=cuentas.TIPO_REVISION_EMERGENCIA, cuenta_afectada_id=beneficiario.pk))
    ok = (primera.estado == "pendiente" and segunda.estado == "activa" and primera.acceso_id == segunda.acceso_id
          and acceso.fin - acceso.inicio == timedelta(hours=4)
          and acceso.revision_vence_en - acceso.inicio == timedelta(hours=24) and acceso.revisado_en is None
          and len(avisos) == 1 and avisos[0].prioridad == "prioritaria" and avisos[0].usuario_id == r7.pk)
    return resultado(ok, f"{primera.estado} y luego {segunda.estado}; vence a 4 h; revisión a 24 h; aviso {avisos[0].prioridad if avisos else '-'}")


def m02():
    d = Datos()
    r4 = d.usuario("R4")
    obtenido = condicion(lambda: cuentas.autorizar_emergencia(r4, r4.pk, "R1"))
    return resultado(obtenido == "Cd24", obtenido)


def m03():
    d = Datos()
    r4, beneficiario = d.usuario("R4"), d.usuario("R1")
    rol = condicion(lambda: cuentas.autorizar_emergencia(r4, beneficiario.pk, "R7"))
    perfil = condicion(lambda: cuentas.autorizar_emergencia(r4, beneficiario.pk, "R2", perfil="aprobar"))
    return resultado(rol == perfil == "Cd24", f"rol suplido R7 {rol}; perfil con aprobación {perfil}")


def m04():
    d = Datos()
    r4, beneficiario = d.usuario("R4"), d.usuario("R1")
    cuentas.autorizar_emergencia(r4, beneficiario.pk, "R1")
    obtenido = condicion(lambda: cuentas.autorizar_emergencia(r4, beneficiario.pk, "R1"))
    return resultado(obtenido == "Cd24", obtenido)


def m05():
    d = Datos()
    beneficiario = d.usuario("R1")
    cuentas.autorizar_emergencia(d.usuario("R4"), beneficiario.pk, "R1")
    obtenido = condicion(lambda: cuentas.autorizar_emergencia(d.usuario("R4"), beneficiario.pk, "R1"))
    return resultado(obtenido == "Cd24", obtenido)


def m06():
    d = Datos()
    original = plazos.leer_parametro
    duraciones = {}
    for horas in (2, 6):
        def lector(clave, horas=horas):
            return Decimal(horas) if clave == cuentas.CLAVE_EMERGENCIA_HORAS else original(clave)
        with mock.patch.object(plazos, "leer_parametro", side_effect=lector):
            _, _, _, _, segunda = emergencia_activa(d)
        acceso = AccesoEmergencia.objects.get(pk=segunda.acceso_id)
        duraciones[horas] = acceso.fin - acceso.inicio
    ok = duraciones == {2: timedelta(hours=2), 6: timedelta(hours=4)}
    return resultado(ok, f"temg_horas 2 -> {duraciones[2]}; temg_horas 6 -> {duraciones[6]} (tope del CHECK)")


def m07():
    d = Datos()
    beneficiario, *_ = emergencia_activa(d, "R2")
    primero = cuentas.consumir_emergencia(beneficiario.pk)
    segundo = condicion(lambda: cuentas.consumir_emergencia(beneficiario.pk))
    return resultado(primero.rol_suplido == "R2" and segundo == "Cd24", f"primer uso {primero.rol_suplido}; segundo {segundo}")


def m08():
    d = Datos()
    beneficiario, r4, r7 = d.usuario("R1"), d.usuario("R4"), d.usuario("R7")
    antes = cuentas.acceso_emergencia_vigente(beneficiario.pk)
    cuentas.autorizar_emergencia(r4, beneficiario.pk, "R1")
    pendiente = cuentas.acceso_emergencia_vigente(beneficiario.pk)
    cuentas.autorizar_emergencia(r7, beneficiario.pk, "R1")
    activa = cuentas.acceso_emergencia_vigente(beneficiario.pk)
    cuentas.consumir_emergencia(beneficiario.pk)
    usada = cuentas.acceso_emergencia_vigente(beneficiario.pk)
    otro = d.usuario("R2")
    d.sql(
        "INSERT INTO usuarios_accesoemergencia (id, beneficiario_id, autorizado_por_r4_id, autorizado_por_r7_id,"
        " rol_suplido_id, perfil, inicio, fin) VALUES (%s, %s, %s, %s, 'R2', 'solo_lectura',"
        " now() - interval '5 hours', now() - interval '1 hour')",
        [uuid.uuid4(), otro.pk, r4.pk, r7.pk],
    )
    vencida = cuentas.acceso_emergencia_vigente(otro.pk)
    ok = (antes, pendiente, activa, usada, vencida) == (None, None, "R1", None, None)
    return resultado(ok, f"sin acceso {antes}; pendiente {pendiente}; activa {activa}; usada {usada}; vencida {vencida}")


# --------------------------------------------------------------------------- recuperación


def r01():
    d = Datos()
    administrador = d.usuario("R4")
    cuenta, secreto = d.cuenta_con_totp(administrador)
    sesion = d.sesion_de(cuenta)
    emitido = cuentas.emitir_recuperacion(administrador, cuenta.pk)
    canje = cuentas.canjear_codigo(emitido.codigo, correo=cuenta.correo, contrasena=FRASE_NUEVA, codigo_totp=codigo_totp(secreto))
    cuenta.refresh_from_db()
    avisos = Alerta.objects.filter(tipo=cuentas.TIPO_RECUPERACION_EMITIDA, cuenta_afectada_id=cuenta.pk).count()
    sesion_cerrada = not Session.objects.filter(session_key=sesion).exists()
    ok = (canje.proposito == "recuperacion" and cuenta.check_password(FRASE_NUEVA) and avisos == 1 and sesion_cerrada
          and emitido.vence_en - hora_de_la_base() <= codigos.VIGENCIA_RECUPERACION)
    return resultado(ok, f"contraseña nueva; aviso a R7={avisos}; sesiones cerradas={sesion_cerrada}; vigencia 30 min")


def fallo(accion) -> str:
    try:
        accion()
    except ReglaIncumplida as error:
        return f"{error.condicion}: {error.motivo}"
    return PASA


def r02():
    d = Datos()
    administrador = d.usuario("R4")
    cuenta, secreto = d.cuenta_con_totp(administrador)
    emitido = cuentas.emitir_recuperacion(administrador, cuenta.pk)
    vencido = codigos.generar()
    d.sql(
        "INSERT INTO usuarios_codigounuso (id, usuario_id, proposito, huella, emitido_por_id, emitido_en, vence_en, intentos_fallidos)"
        " VALUES (%s, %s, 'recuperacion', %s, %s, now() - interval '2 hours', now() - interval '1 hour', 0)",
        [uuid.uuid4(), cuenta.pk, codigos.huella(vencido), administrador.pk],
    )
    casos = {
        "incorrecto": lambda: cuentas.canjear_codigo(codigos.generar(), correo=cuenta.correo, contrasena=FRASE_NUEVA, codigo_totp=codigo_totp(secreto)),
        "vencido": lambda: cuentas.canjear_codigo(vencido, correo=cuenta.correo, contrasena=FRASE_NUEVA, codigo_totp=codigo_totp(secreto)),
        "totp incorrecto": lambda: cuentas.canjear_codigo(emitido.codigo, correo=cuenta.correo, contrasena=FRASE_NUEVA, codigo_totp=totp_incorrecto(secreto)),
        "cuenta inexistente": lambda: cuentas.canjear_codigo(emitido.codigo, correo=correo_nuevo(), contrasena=FRASE_NUEVA, codigo_totp=codigo_totp(secreto)),
    }
    obtenidos = {nombre: fallo(accion) for nombre, accion in casos.items()}
    otra = d.cuenta_con_totp(administrador)
    usado = cuentas.emitir_recuperacion(administrador, otra[0].pk)
    cuentas.canjear_codigo(usado.codigo, correo=otra[0].correo, contrasena=FRASE_NUEVA, codigo_totp=codigo_totp(otra[1]))
    obtenidos["usado"] = fallo(lambda: cuentas.canjear_codigo(
        usado.codigo, correo=otra[0].correo, contrasena=FRASE_LARGA, codigo_totp=totp_incorrecto(otra[1])))
    iguales = len(set(obtenidos.values())) == 1 and next(iter(obtenidos.values())).startswith("RECUPERACION")
    return resultado(iguales, f"{len(obtenidos)} fallas con la misma excepción genérica={iguales}")


def r03():
    d = Datos()
    administrador = d.usuario("R4")
    cuenta, secreto = d.cuenta_con_totp(administrador)
    emitido = cuentas.emitir_recuperacion(administrador, cuenta.pk)
    for _ in range(5):
        fallo(lambda: cuentas.canjear_codigo(codigos.generar(), correo=cuenta.correo, contrasena=FRASE_NUEVA))
    intentos = CodigoUnUso.objects.filter(huella=codigos.huella(emitido.codigo)).values_list("intentos_fallidos", flat=True).get()
    correcto = fallo(lambda: cuentas.canjear_codigo(emitido.codigo, correo=cuenta.correo, contrasena=FRASE_NUEVA, codigo_totp=codigo_totp(secreto)))
    return resultado(intentos == 5 and correcto.startswith("RECUPERACION"), f"intentos={intentos}; el código correcto queda invalidado={correcto.startswith('RECUPERACION')}")


def r04():
    d = Datos()
    administrador = d.usuario("R4")
    correo = correo_nuevo()
    alta = cuentas.alta_cuenta(administrador, correo, "Cuenta nueva")
    comun = next(p for p in sorted(CommonPasswordValidator().passwords) if len(p) >= 12 and not p.isdigit())
    obtenido = condicion(lambda: cuentas.canjear_codigo(alta.codigo, correo=correo, contrasena=comun))
    sin_usar = CodigoUnUso.objects.get(usuario_id=alta.usuario_id).usado_en is None
    return resultado(obtenido == "CONTRASENA" and sin_usar, f"contraseña común {obtenido}; código sin consumir={sin_usar}")


def r05():
    d = Datos()
    administrador = d.usuario("R4")
    correo = correo_nuevo()
    alta = cuentas.alta_cuenta(administrador, correo, "Cuenta nueva")
    obtenido = condicion(lambda: cuentas.canjear_codigo(alta.codigo, correo=correo, contrasena=FRASE_LARGA))
    largo = len(FRASE_LARGA) >= 64 and " " in FRASE_LARGA
    return resultado(obtenido == PASA and largo, f"frase de {len(FRASE_LARGA)} caracteres con espacios: {obtenido}")


def r06():
    d = Datos()
    cuenta, _ = d.cuenta_con_totp(d.usuario("R4"))
    algoritmo = cuenta.password.split("$", 2)[:2]
    return resultado(algoritmo == ["argon2", "argon2id"], f"hash {'$'.join(algoritmo)}")


def r07():
    d = Datos()
    administrador = d.usuario("R4")
    cuenta, _ = d.cuenta_con_totp(administrador)
    emitido = cuentas.emitir_recuperacion(administrador, cuenta.pk)
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT count(*) FROM usuarios_codigounuso c WHERE strpos(row_to_json(c)::text, %s) > 0", [emitido.codigo]
        )
        en_claro = cursor.fetchone()[0]
    con_huella = CodigoUnUso.objects.filter(huella=codigos.huella(emitido.codigo)).count()
    return resultado(en_claro == 0 and con_huella == 1, f"filas con el código en claro={en_claro}; con su huella={con_huella}")


# --------------------------------------------------------------------------- ejecución

PRUEBAS = [
    ("K01", "Propósito catálogo sin R3 no ve mediciones", "0; con R3 1", pc.c33),
    ("K02", "Registrar medición en parcela dada de baja", "VIGENCIA", pc.c34),
    ("K03", "La baja de la parcela termina las asignaciones vigentes", "fin = fecha de baja", pc.c35),
    ("A01", "Alta de cuenta", "creado_por = actor, sin contraseña ni roles", a01),
    ("A02", "Canje del código de alta", "contraseña y TOTP", a02),
    ("A03", "Modificar cuenta no toca roles", "pasa", a03),
    ("A04", "Asignar rol sin conflicto (caso 43)", "pasa", a04),
    ("A05", "Asignar R2 a quien tiene R1 (caso 42)", "Cd13", a05),
    ("A06", "Autoasignación de rol (caso 44)", "Cd13", a06),
    ("A07", "Asignar R3 a quien tiene R2 (caso 70)", "Cd13", a07),
    ("A08", "Asignar R4 a quien tiene R3", "pasa", a08),
    ("A09", "Revocarse un rol propio", "Cd13", a09),
    ("A10", "Baja de cuenta", "inactiva, sesiones y códigos invalidados", a10),
    ("A11", "Darse de baja a sí mismo", "Cd13", a11),
    ("A12", "Aviso de catálogo sobre una cuenta dada de alta por el actor", "prioritaria", a12),
    ("W01", "Solicitar ventana (caso 63)", "solicitada, sin acceso", w01),
    ("W02", "Abrir con solicitud y 20 días acumulados (caso 60)", "abierta", w02),
    ("W03", "Abrir sin solicitud (caso 61)", "Cd23", w03),
    ("W04", "Abrir pasando de 30 días en el año (caso 62)", "Cd23", w04),
    ("W05", "Ventana para una cuenta que no es R5", "Cd23", w05),
    ("W06", "Abrir la ventana que uno mismo solicitó", "Cd23", w06),
    ("W07", "Abrir una solicitud ya abierta", "Cd23", w07),
    ("W08", "Ventana abierta y vigente da acceso", "True", w08),
    ("M01", "Emergencia: primera pendiente, segunda distinta activa (caso 64)", "pendiente; activa", m01),
    ("M02", "Beneficiario que es autorizador (caso 65)", "Cd24", m02),
    ("M03", "Rol suplido no R1/R2 o perfil con aprobación (caso 66)", "Cd24, Cd24", m03),
    ("M04", "Mismo autorizador dos veces", "Cd24", m04),
    ("M05", "Dos autorizadores con el mismo rol", "Cd24", m05),
    ("M06", "Vence a temg_horas con el tope del CHECK", "2 h; 4 h", m06),
    ("M07", "Segundo uso del acceso", "Cd24", m07),
    ("M08", "acceso_emergencia_vigente respeta activación, uso y vencimiento", "R1 solo activa y sin usar", m08),
    ("R01", "Recuperación con código y TOTP válidos", "pasa", r01),
    ("R02", "Código incorrecto, vencido, usado, TOTP incorrecto o cuenta inexistente", "misma excepción genérica", r02),
    ("R03", "Cinco intentos fallidos invalidan el código", "invalidado", r03),
    ("R04", "Contraseña común rechazada", "CONTRASENA", r04),
    ("R05", "Frase larga con espacios aceptada", "pasa", r05),
    ("R06", "Contraseña almacenada con Argon2id", "argon2id", r06),
    ("R07", "El código no queda en claro en la base", "0", r07),
]


def conteos() -> dict[str, int]:
    original = ps.TABLAS_CONTEO
    ps.TABLAS_CONTEO = TABLAS_CONTEO
    try:
        return ps.conteos()
    finally:
        ps.TABLAS_CONTEO = original


def main() -> int:
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    try:
        ps.usar(ps.APP)
        iniciales = conteos()
        resultados = [ps.ejecutar(*prueba) for prueba in PRUEBAS]
        finales = conteos()
    except ps.DatabaseError as error:
        raise SystemExit(f"[FALLO] Error de base de datos {ps._sqlstate(error)}") from None
    finally:
        ps.connections["default"].close()
    pm.imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    print(f"\nTotal: {correctas}/{len(resultados)} OK")
    limpio = finales == iniciales
    print(f"Conteos antes: {iniciales}")
    print(f"Conteos después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio else 1


if __name__ == "__main__":
    sys.exit(main())
