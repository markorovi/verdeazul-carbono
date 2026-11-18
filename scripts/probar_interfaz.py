#!/usr/bin/env python3
"""Pruebas de extremo a extremo de la interfaz web contra la base dev.

Uso (en una sesión con las variables cargadas):
    . .\\scripts\\entorno_dev.ps1 -Pruebas
    python scripts/probar_interfaz.py            # todas
    python scripts/probar_interfaz.py I09 B1     # solo las que empiezan así

Cada prueba hace peticiones HTTP con el cliente de pruebas de Django (en el mismo proceso) y corre en
una transacción que SIEMPRE se revierte; al final se comparan los conteos con los iniciales. La
bitácora es un servicio real sobre un esquema temporal (como en probar_bitacora.py), que se destruye
al terminar. El PDP es el motor de Python; si existe .opa_local.json, un subconjunto representativo
corre además con OPA. Las contraseñas, los códigos TOTP y los códigos de un solo uso son sintéticos y
nunca se imprimen: solo se imprimen resultados, totales y conteos.
"""

from __future__ import annotations

import hashlib
import http.cookiejar
import itertools
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

if os.environ.get("ENTORNO") != "local" or "VERDEAZUL_PROD" in os.environ:
    raise SystemExit("[FALLO] Solo corre con ENTORNO=local y sin VERDEAZUL_PROD.")
os.environ["PDP_BACKEND"] = "python"

import probar_bitacora as pb  # noqa: E402  (configura Django, app_rw y la bitácora de prueba)

from django.core.servers.basehttp import ThreadedWSGIServer  # noqa: E402
from django.core.signals import request_finished, request_started  # noqa: E402
from django.core.handlers.wsgi import WSGIHandler  # noqa: E402
from django.db import close_old_connections, connection, connections  # noqa: E402
from django.test import Client, override_settings  # noqa: E402
from django.test.testcases import LiveServerThread  # noqa: E402
from django.urls import URLPattern, URLResolver, get_resolver  # noqa: E402

import probar_autorizacion as pa  # noqa: E402
import probar_catalogo as pc  # noqa: E402
import probar_cuentas as pk  # noqa: E402
import probar_mediciones as pm  # noqa: E402
import probar_servicios as ps  # noqa: E402
from bitacora_svc import esquema  # noqa: E402
from catalogo import servicios as catalogo  # noqa: E402
from interfaz import limites, registro, web  # noqa: E402
from mediciones import alertas, firma, servicios  # noqa: E402
from mediciones.models import Alerta, Certificado, Medicion  # noqa: E402
from mediciones.transaccion import hora_de_la_base  # noqa: E402
from usuarios import autenticacion, totp  # noqa: E402
from usuarios import servicios as cuentas  # noqa: E402
from usuarios.views import MENSAJE_FALLO  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
HOST = "localhost"
PASA = ps.PASA
DENEGADAS = sorted(pa.DENEGADAS_A_TODOS)
OPA_SUBCONJUNTO = ("O1.Ap", "O3.Ex", "O6.AR-asignar", "O1.L", "O1.MdC")
NOTA_SCRIPT = "<script>alert(1)</script>"
PATRON_CSRF = re.compile(r'name="csrfmiddlewaretoken" value="[^"]*"')
PATRON_HUELLA = re.compile(r'name="huella_revisada" value="([0-9a-f]{64})"')
TABLA_INTENTOS = "interfaz_intentofallido"
INSTANCIA: pb.Instancia | None = None
_IPS = itertools.count(1)


# --------------------------------------------------------------------------- cliente HTTP


def cliente(csrf: bool = False, ip: str | None = None) -> Client:
    """Cada cliente sale de una IP distinta (rango de documentación), salvo que se indique."""
    n = next(_IPS)
    return Client(HTTP_HOST=HOST, REMOTE_ADDR=ip or f"198.51.{n // 250}.{n % 250 + 1}", enforce_csrf_checks=csrf)


def entrar(c: Client, usuario, edad: int = 30) -> Client:
    """Sesión ya autenticada con segundo factor hace `edad` segundos (sin pasar por el formulario)."""
    c.force_login(usuario, backend=autenticacion.RUTA_BACKEND)
    sesion = c.session
    sesion[autenticacion.CLAVE_MFA] = time.time() - edad
    sesion.save()
    return c


def como(usuario, edad: int = 30) -> Client:
    return entrar(cliente(), usuario, edad)


def texto(r) -> str:
    return r.content.decode("utf-8", errors="replace")


def completada(r, codigo: str) -> bool:
    return r.status_code == 200 and f"Operación {codigo} completada." in texto(r)


def denegada(r, regla: str) -> bool:
    return r.status_code == 403 and f'<span class="regla">{regla}</span>' in texto(r)


def ruta(clave: str, objeto=None) -> str:
    entrada = registro.POR_CLAVE[clave]
    return f"/operaciones/{entrada.clave}/{f'{objeto}/' if entrada.con_objeto else ''}"


def estado(r) -> str:
    return f"HTTP {r.status_code}"


def eventos_de(usuario, limite: int = 30) -> list[dict]:
    return INSTANCIA.cliente.consultar(usuario_id=str(usuario.pk), limite=limite, orden="desc")


def reiniciar_totp(usuario) -> None:
    with connection.cursor() as cursor:
        cursor.execute("UPDATE usuarios_usuario SET totp_ultimo_paso = NULL WHERE id = %s", [usuario.pk])


def iniciar_sesion(c: Client, usuario, secreto: str, siguiente: str | None = None):
    """Acceso real en dos pasos. El código TOTP se calcula aquí y nunca se imprime."""
    reiniciar_totp(usuario)
    datos = {"correo": usuario.correo, "password": pk.FRASE_LARGA}
    if siguiente is not None:
        datos["next"] = siguiente
    paso1 = c.post("/acceso/", datos)
    paso2 = c.post("/acceso/segundo-factor/", {"codigo": totp.codigo_para(secreto, time.time())})
    return paso1, paso2


def fecha_hora(momento) -> str:
    return momento.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M")


# --------------------------------------------------------------------------- rutas


def rutas_concretas():
    """(ruta concreta, patrón) de cada URL, con un UUID en lugar de <uuid:objeto_id>."""
    def recorrer(patrones, prefijo=""):
        for patron in patrones:
            if isinstance(patron, URLResolver):
                yield from recorrer(patron.url_patterns, prefijo + str(patron.pattern))
            elif isinstance(patron, URLPattern):
                yield prefijo + str(patron.pattern), patron

    for plantilla, patron in recorrer(get_resolver().url_patterns):
        if "<path:" in plantilla:
            continue
        yield "/" + plantilla.replace("<uuid:objeto_id>", str(uuid.uuid4())), patron


def marca(patron):
    return getattr(patron.callback, web.MARCA, (None, None))


# --------------------------------------------------------------------------- I01 a I03


def i01():
    protegidas = [r for r, p in rutas_concretas() if marca(p)[0] in (web.OPERACION, web.SESION)]
    c = cliente()
    malas = []
    for r in protegidas:
        respuesta = c.get(r)
        if not (respuesta.status_code == 302 and respuesta["Location"].startswith("/acceso/?next=")):
            malas.append(r)
    return not malas and len(protegidas) > 40, f"{len(protegidas)} rutas protegidas; sin redirigir: {len(malas)}"


def i02():
    d = pa.Datos()
    usuario, secreto = d.cuenta_con_totp(d.usuario("R4"))
    c = cliente()
    clave_mala = c.post("/acceso/", {"correo": usuario.correo, "password": "contrasena-incorrecta-de-prueba"})
    inexistente = cliente().post("/acceso/", {"correo": f"nadie-{uuid.uuid4().hex[:8]}@{pk.DOMINIO}",
                                             "password": "contrasena-incorrecta-de-prueba"})
    genericas = (MENSAJE_FALLO in texto(clave_mala)
                 and PATRON_CSRF.sub("", texto(clave_mala)) == PATRON_CSRF.sub("", texto(inexistente)))
    reiniciar_totp(usuario)
    paso1 = c.post("/acceso/", {"correo": usuario.correo, "password": pk.FRASE_LARGA, "next": "/operaciones/"})
    malo = c.post("/acceso/segundo-factor/", {"codigo": pk.totp_incorrecto(secreto)})
    bueno = c.post("/acceso/segundo-factor/", {"codigo": totp.codigo_para(secreto, time.time())})
    galleta = bueno.cookies.get("sessionid")
    banderas = bool(galleta) and bool(galleta["httponly"]) and galleta["samesite"] == "Lax"
    ok_pasos = (paso1.status_code == 302 and MENSAJE_FALLO in texto(malo)
                and bueno.status_code == 302 and bueno["Location"] == "/operaciones/")
    c.post("/salida/")
    _, abierta = iniciar_sesion(cliente(), usuario, secreto, siguiente="https://evil.example/")
    sin_redireccion_abierta = abierta.status_code == 302 and abierta["Location"] == "/cuenta/"
    ok = genericas and ok_pasos and banderas and sin_redireccion_abierta
    return ok, (f"fallos genéricos e idénticos={genericas}; TOTP malo y bueno={ok_pasos}; HttpOnly y SameSite=Lax={banderas}"
                f" (Secure solo fuera de local); next externo a /cuenta/={sin_redireccion_abierta}")


def i03():
    d = pa.Datos()
    estricto = entrar(cliente(csrf=True), d.usuario("R7"))
    rutas_post = []
    for r, p in rutas_concretas():
        if marca(p)[0] == web.OPERACION and r.startswith("/operaciones/"):
            rutas_post.append(r)
        elif p.name in ("salida", "acceso", "segundo_factor", "reautenticar", "recuperar", "verificar"):
            rutas_post.append(r)
    respuestas = {r: estricto.post(r, {}).status_code for r in rutas_post}
    malas = [r for r, codigo in respuestas.items() if codigo != 403]
    return not malas and len(rutas_post) >= 40, f"{len(rutas_post)} rutas POST sin token; distintas de 403: {len(malas)}"


# --------------------------------------------------------------------------- I04: las 41 operaciones


def op_o1_rg(d):
    ctx = d.finca()
    ctx["parcela"] = d.parcela(ctx)
    tecnico = d.usuario("R1")
    catalogo.asignar_tecnico(ctx["r3"], ctx["parcela"], tecnico.pk, hora_de_la_base() + timedelta(days=30))
    periodo = servicios.abrir_periodo(ctx["r7"], ps.INICIO, ps.FIN).periodo_id
    return como(tecnico).post(ruta("O1.Rg", ctx["parcela"]), {
        "periodo_id": periodo, "co2e_toneladas": "100.000", "fecha_muestreo": "2026-01-15", "notas": ""})


def op_o1_md(d):
    ctx = d.base()
    return como(ctx["tecnico"]).post(ruta("O1.Md", ctx["medicion"]), {
        "co2e_toneladas": "150.000", "fecha_muestreo": "2026-02-01", "notas": "corregida"})


def op_o1_pr(d):
    ctx = d.base()
    return como(ctx["tecnico"]).post(ruta("O1.Pr", ctx["medicion"]), {})


def op_o1_ap(d):
    ctx = d.cerrada()
    c = como(ctx["r2"])
    revision = c.get(ruta("O1.Ap", ctx["medicion"]))
    encontrada = PATRON_HUELLA.search(texto(revision))
    return c.post(ruta("O1.Ap", ctx["medicion"]), {"huella_revisada": encontrada.group(1) if encontrada else ""})


def op_o1_dv(d):
    ctx = d.cerrada()
    return como(ctx["r2"]).post(ruta("O1.Dv", ctx["medicion"]), {"huella_revisada": ctx["huella"]})


def op_o1_rs(d):
    ctx = d.cerrada()
    return como(ctx["r7"]).post(ruta("O1.Rs", ctx["medicion"]), {"destino_id": ctx["r2"].pk})


def op_o2_ab(d):
    return como(d.usuario("R7")).post(ruta("O2.Ab"), {"inicio": ps.INICIO.isoformat(), "fin": ps.FIN.isoformat()})


def op_o2_ci(d):
    ctx = d.presentada()
    return como(ctx["r7"]).post(ruta("O2.Ci", ctx["periodo"]), {})


def op_o3_an(d):
    ctx = d.certificada()
    return como(ctx["r7"]).post(ruta("O3.An", ctx["certificado"]), {"justificacion": pa.JUSTIFICACION})


def op_o3_ex(d):
    ctx = pa.certificado_de_finca(d)
    return como(ctx["propietarios"][0]).post(ruta("O3.Ex", ctx["certificado"]), {})


def op_o4_so(d):
    ctx = d.cerrada()
    return como(ctx["tecnico"]).post(ruta("O4.So", ctx["medicion"]), {
        "motivo": ps.MOTIVO, "co2e_nuevo": "120.000", "fecha_nueva": "2026-02-01", "notas_nuevas": ""})


def op_o4_au(d):
    ctx = d.cerrada()
    enmienda = servicios.solicitar_enmienda(ctx["tecnico"], ctx["medicion"], motivo=ps.MOTIVO,
                                            co2e_nuevo=ps.CO2E_CORREGIDO, fecha_nueva=ps.FECHA_CORREGIDA).enmienda_id
    return como(ctx["r7b"]).post(ruta("O4.Au", enmienda), {"decision": "autorizar"})


def op_o5_cr_finca(d):
    return como(d.usuario("R3")).post(ruta("O5.Cr-finca"), {"nombre": "Finca por la interfaz",
                                                             "propietarios": str(d.usuario("R6").pk)})


def op_o5_cr_parcela(d):
    ctx = d.finca()
    return como(ctx["r3"]).post(ruta("O5.Cr-parcela", ctx["finca"]), {"codigo": "P-web", "wkt": pc.cuadrado(7)})


def op_o5_md_parcela(d):
    ctx = d.finca()
    parcela = d.parcela(ctx)
    return como(ctx["r3"]).post(ruta("O5.Md-parcela", parcela), {"codigo": "P-renombrada", "wkt": ""})


def op_o5_md_propietarios(d):
    ctx = d.finca()
    return como(ctx["r3"]).post(ruta("O5.Md-propietarios", ctx["finca"]), {"agregar": str(d.usuario("R6").pk),
                                                                            "retirar": ""})


def op_o5_as(d):
    ctx = d.finca()
    parcela = d.parcela(ctx)
    return como(ctx["r3"]).post(ruta("O5.As", parcela), {
        "tecnico_id": d.usuario("R1").pk, "vence_en": fecha_hora(hora_de_la_base() + timedelta(days=10))})


def op_o5_ba(d):
    ctx = d.finca()
    parcela = d.parcela(ctx)
    return como(ctx["r3"]).post(ruta("O5.Ba", parcela), {})


def op_o6_al(d):
    return como(d.usuario("R4")).post(ruta("O6.Al"), {"correo": pk.correo_nuevo(), "nombre": "Cuenta por la interfaz"})


def op_o6_md_cuenta(d):
    return como(d.usuario("R4")).post(ruta("O6.Md-cuenta", d.usuario("R1").pk), {"nombre": "Nombre corregido"})


def op_o6_md_recuperacion(d):
    cuenta, _ = d.cuenta_con_totp(d.usuario("R4"))
    return como(d.usuario("R4")).post(ruta("O6.Md-recuperacion", cuenta.pk), {})


def op_o6_ar_asignar(d):
    return como(d.usuario("R4")).post(ruta("O6.AR-asignar", d.usuario().pk), {"rol": "R1"})


def op_o6_ar_revocar(d):
    return como(d.usuario("R4")).post(ruta("O6.AR-revocar", d.usuario("R1").pk), {"rol": "R1"})


def op_o6_ba(d):
    return como(d.usuario("R4")).post(ruta("O6.Ba", d.usuario("R1").pk), {})


def op_o6_sv(d):
    ahora = hora_de_la_base()
    return como(d.usuario("R7")).post(ruta("O6.Sv", d.usuario("R5").pk), {
        "inicio": fecha_hora(ahora - timedelta(hours=1)), "fin": fecha_hora(ahora + timedelta(days=1))})


def op_o6_av(d):
    ahora = hora_de_la_base()
    ventana = cuentas.solicitar_ventana(d.usuario("R7"), d.usuario("R5").pk, ahora - timedelta(hours=1),
                                        ahora + timedelta(days=1)).ventana_id
    return como(d.usuario("R4")).post(ruta("O6.Av", ventana), {})


def op_o6_ae(d):
    return como(d.usuario("R4")).post(ruta("O6.Ae", d.usuario("R1").pk), {"rol_suplido": "R2"})


def op_o8_rs(d):
    ctx = d.finca()
    d.actor(ctx["r7"])
    alerta = Alerta.objects.filter(tipo=alertas.TIPO_ALTA_FINCA, detalle__finca_id=str(ctx["finca"])).values_list(
        "pk", flat=True).first()
    return como(ctx["r7"]).post(ruta("O8.Rs", alerta), {"justificacion": pa.JUSTIFICACION})


def lee_o1(d):
    ctx = d.base()
    return como(ctx["r7"]).get(f"/mediciones/{ctx['medicion']}/")


def lee_o2(d):
    return como(d.usuario("R7")).get("/periodos/")


def lee_o3(d):
    ctx = pa.certificado_de_finca(d)
    return como(ctx["propietarios"][0]).get(f"/certificados/{ctx['certificado']}/")


def lee_o4(d):
    ctx = d.cerrada()
    enmienda = servicios.solicitar_enmienda(ctx["tecnico"], ctx["medicion"], motivo=ps.MOTIVO,
                                            co2e_nuevo=ps.CO2E_CORREGIDO, fecha_nueva=ps.FECHA_CORREGIDA).enmienda_id
    return como(ctx["r7"]).get(f"/enmiendas/{enmienda}/")


def lee_o5(d):
    ctx = d.finca()
    return como(ctx["r3"]).get(f"/catalogo/parcelas/{d.parcela(ctx)}/")


def lee_o6(d):
    return como(d.usuario("R4")).get(f"/cuentas/{d.usuario('R1').pk}/")


def lee_o7(d):
    return como(d.usuario("R7")).get("/bitacora/")


def lee_o8(d):
    return como(d.usuario("R7")).get("/alertas/")


ESCRITURAS = {
    "O1.Rg": op_o1_rg, "O1.Md": op_o1_md, "O1.Pr": op_o1_pr, "O1.Ap": op_o1_ap, "O1.Dv": op_o1_dv, "O1.Rs": op_o1_rs,
    "O2.Ab": op_o2_ab, "O2.Ci": op_o2_ci, "O3.An": op_o3_an, "O3.Ex": op_o3_ex, "O4.So": op_o4_so, "O4.Au": op_o4_au,
    "O5.Cr-finca": op_o5_cr_finca, "O5.Cr-parcela": op_o5_cr_parcela, "O5.Md-parcela": op_o5_md_parcela,
    "O5.Md-propietarios": op_o5_md_propietarios, "O5.As": op_o5_as, "O5.Ba": op_o5_ba, "O6.Al": op_o6_al,
    "O6.Md-cuenta": op_o6_md_cuenta, "O6.Md-recuperacion": op_o6_md_recuperacion, "O6.AR-asignar": op_o6_ar_asignar,
    "O6.AR-revocar": op_o6_ar_revocar, "O6.Ba": op_o6_ba, "O6.Sv": op_o6_sv, "O6.Av": op_o6_av, "O6.Ae": op_o6_ae,
    "O8.Rs": op_o8_rs,
}
LECTURAS = {"O1.L": lee_o1, "O2.L": lee_o2, "O3.L": lee_o3, "O4.L": lee_o4, "O5.L": lee_o5, "O6.L": lee_o6,
            "O7.L": lee_o7, "O8.L": lee_o8}


def caso_escritura(clave):
    def prueba():
        r = ESCRITURAS[clave](pa.Datos())
        codigo = registro.POR_CLAVE[clave].codigo
        if codigo == "O3.Ex":
            ok = r.status_code == 200 and r.get("Content-Disposition", "").startswith("attachment;")
            return ok, f"{estado(r)}, adjunto={ok}"
        return completada(r, codigo), estado(r)
    return prueba


def caso_lectura(codigo):
    def prueba():
        r = LECTURAS[codigo](pa.Datos())
        # Las listas (O2.L, O7.L, O8.L) pueden no tener filas visibles; los detalles siempre traen su ficha.
        ok = r.status_code == 200 and (codigo in ("O2.L", "O7.L", "O8.L") or 'class="ficha"' in texto(r))
        return ok, estado(r)
    return prueba


def caso_denegada(codigo):
    def prueba():
        d = pa.Datos()
        usuario = d.usuario("R7")
        r = como(usuario).post(ruta(codigo), {})
        registrado = any(e.get("operacion") == codigo and e.get("accion") == "denegacion" and e.get("regla") == "defecto"
                         for e in eventos_de(usuario))
        return denegada(r, "defecto") and registrado, f"{estado(r)} regla defecto; en bitácora={registrado}"
    return prueba


# --------------------------------------------------------------------------- I05 a I14


def i05():
    d = pa.Datos()
    ctx = d.finca()
    ctx["parcela"] = d.parcela(ctx)
    ctx.update(tecnico=d.usuario("R1"), r2=d.usuario("R2"), r2b=d.usuario("R2"), r4=d.usuario("R4"))
    catalogo.asignar_tecnico(ctx["r3"], ctx["parcela"], ctx["tecnico"].pk, hora_de_la_base() + timedelta(days=30))
    ctx["periodo"] = servicios.abrir_periodo(ctx["r7"], ps.INICIO, ps.FIN).periodo_id
    nota = f"nota-de-proyeccion-{uuid.uuid4().hex[:8]}"
    registro_m = servicios.registrar_medicion(ctx["tecnico"], ctx["parcela"], ctx["periodo"], co2e_toneladas=ps.CO2E_BAJO,
                                              fecha_muestreo=ps.FECHA, notas=nota)
    servicios.presentar_medicion(ctx["tecnico"], registro_m.medicion_id)
    servicios.cerrar_periodo(ctx["r7"], ctx["periodo"])
    certificado = servicios.aprobar_medicion(ctx["r2"], registro_m.medicion_id,
                                             huella_revisada=registro_m.huella).certificado_id
    aprobador = firma.seudonimo(ctx["r2"].pk)
    vistas = {
        "R7": texto(como(ctx["r7"]).get(f"/certificados/{certificado}/")),
        "R6": texto(como(ctx["propietarios"][0]).get(f"/certificados/{certificado}/")),
        "R1": texto(como(ctx["tecnico"]).get(f"/certificados/{certificado}/")),
    }
    campos = {rol: set(re.findall(r'data-campo="([a-z_]+)"', cuerpo)) for rol, cuerpo in vistas.items()}
    medicion_r7 = texto(como(ctx["r7"]).get(f"/mediciones/{registro_m.medicion_id}/"))
    medicion_r6 = texto(como(ctx["propietarios"][0]).get(f"/mediciones/{registro_m.medicion_id}/"))
    ok = (campos["R7"] != campos["R6"] != campos["R1"] and "aprobadores" in campos["R7"]
          and "aprobadores" not in campos["R6"] | campos["R1"] and aprobador in vistas["R7"]
          and aprobador not in vistas["R6"] and aprobador not in vistas["R1"]
          and registro_m.huella not in vistas["R6"] and nota in medicion_r7 and nota not in medicion_r6
          and 'data-campo="co2e_toneladas"' in medicion_r6)
    return ok, (f"campos certificado R7={len(campos['R7'])}, R6={len(campos['R6'])}, R1={len(campos['R1'])};"
                f" excluidos ausentes del cuerpo={ok}")


def i06():
    d = pa.Datos()
    propio = d.certificada(ctx={**d.finca(), "indice": 7})
    ajeno = d.certificada(ctx={**d.finca(), "indice": 8})
    dueno = propio["propietarios"][0]
    c = como(dueno)
    lista = texto(c.get("/certificados/"))
    detalle_ajeno = c.get(f"/certificados/{ajeno['certificado']}/")
    ok = (str(propio["certificado"]) in lista and str(ajeno["certificado"]) not in lista
          and detalle_ajeno.status_code == 403)
    return ok, f"lista con el propio={str(propio['certificado']) in lista}, sin el ajeno={str(ajeno['certificado']) not in lista}; detalle ajeno {estado(detalle_ajeno)}"


def i07():
    d = pa.Datos()
    ctx = d.certificada()
    d.actor(ctx["r7"])
    cert = Certificado.objects.get(pk=ctx["certificado"])
    documento = {"payload": cert.payload, "signature": cert.firma, "public_key": cert.clave_publica, "alg": cert.alg}
    propio = json.dumps(documento)
    otra = json.dumps(firma.firmar(cert.payload | {}, pb.Ed25519PrivateKey.generate()))
    valor = cert.payload["co2e_toneladas"]
    alterado = propio.replace(f'"{valor}"', f'"{valor[:-1]}{"1" if valor[-1] != "1" else "2"}"', 1)
    c = cliente()
    conclusiones = {}
    for nombre, cuerpo in (("propio", propio), ("otra_clave", otra), ("alterado", alterado), ("formato", "{")):
        r = c.post("/verificar/", {"certificado": cuerpo})
        encontrada = re.search(r'data-conclusion="([a-z_]+)"', texto(r))
        conclusiones[nombre] = encontrada.group(1) if encontrada else estado(r)
    from django.core.files.uploadedfile import SimpleUploadedFile

    archivo = c.post("/verificar/", {"archivo": SimpleUploadedFile("cert.json", propio.encode(), "application/json")})
    por_archivo = 'data-conclusion="integro_verdeazul"' in texto(archivo)
    grande = c.post("/verificar/", {"certificado": "x" * 70000}).status_code
    esperado = {"propio": "integro_verdeazul", "otra_clave": "integro_otra_clave", "alterado": "alterado",
                "formato": "formato_invalido"}
    un_byte = len(propio) == len(alterado) and sum(a != b for a, b in zip(propio, alterado)) == 1
    ok = conclusiones == esperado and por_archivo and grande == 413 and un_byte
    return ok, f"{conclusiones}; archivo={por_archivo}; >64 KiB HTTP {grande}"


def i08():
    d = pa.Datos()
    ctx = pa.certificado_de_finca(d)
    dueno = ctx["propietarios"][0]
    r = como(dueno).post(ruta("O3.Ex", ctx["certificado"]), {})
    huella = hashlib.sha256(r.content).hexdigest()
    registrada = [e.get("huella_exportacion") for e in eventos_de(dueno) if e.get("accion") == "exportacion"]
    ok = (r.status_code == 200 and r["X-Content-Type-Options"] == "nosniff"
          and r["Content-Disposition"].startswith("attachment;") and registrada[:1] == [huella])
    return ok, f"{estado(r)}; SHA-256 del contenido en la bitácora={registrada[:1] == [huella]}"


def i09():
    d = pa.Datos()
    ctx = d.cerrada()
    c = como(ctx["r2"])
    revision = c.get(ruta("O1.Ap", ctx["medicion"]))
    mostrada = PATRON_HUELLA.search(texto(revision)).group(1)
    enmienda = servicios.solicitar_enmienda(ctx["tecnico"], ctx["medicion"], motivo=ps.MOTIVO,
                                            co2e_nuevo=ps.CO2E_CORREGIDO, fecha_nueva=ps.FECHA_CORREGIDA).enmienda_id
    servicios.resolver_enmienda(ctx["r7b"], enmienda, autorizar=True)
    vieja = c.post(ruta("O1.Ap", ctx["medicion"]), {"huella_revisada": mostrada})
    d.actor(ctx["r7"])
    sin_aprobar = Medicion.objects.filter(pk=ctx["medicion"]).values_list("estado", flat=True).get() == "presentada"
    nueva = PATRON_HUELLA.search(texto(c.get(ruta("O1.Ap", ctx["medicion"])))).group(1)
    aprobada = c.post(ruta("O1.Ap", ctx["medicion"]), {"huella_revisada": nueva})
    ok = mostrada == ctx["huella"] and denegada(vieja, "Cd7") and sin_aprobar and nueva != mostrada and completada(aprobada, "O1.Ap")
    return ok, f"huella vieja {estado(vieja)} Cd7={denegada(vieja, 'Cd7')}; sin aprobar={sin_aprobar}; huella nueva {estado(aprobada)}"


def i10():
    d = pa.Datos()
    usuario, secreto = d.cuenta_con_totp(d.usuario("R4"))
    with mock.patch.object(limites, "LIMITE", 3):
        fija = "203.0.113.77"
        c = cliente(ip=fija)
        fallos = [c.post("/acceso/", {"correo": usuario.correo, "password": "contrasena-incorrecta-de-prueba"}).status_code
                  for _ in range(3)]
        bloqueada = c.post("/acceso/", {"correo": usuario.correo, "password": pk.FRASE_LARGA}).status_code
        # Cambiar la primera entrada de X-Forwarded-For no evade el límite: cuenta la última (la de Cloud Run).
        falsificada = cliente(ip="10.9.9.9").post("/acceso/", {"correo": usuario.correo, "password": pk.FRASE_LARGA},
                                                 HTTP_X_FORWARDED_FOR=f"192.0.2.{next(_IPS) % 250}, {fija}").status_code
        otra_ip = cliente().post("/acceso/", {"correo": usuario.correo, "password": pk.FRASE_LARGA}).status_code
        r = cliente(ip="203.0.113.78")
        canjes = [r.post("/recuperar/", {"correo": usuario.correo, "codigo": "codigo-falso", "contrasena": pk.FRASE_NUEVA,
                                         "confirmacion": pk.FRASE_NUEVA, "codigo_totp": ""}).status_code for _ in range(3)]
        canje_bloqueado = r.post("/recuperar/", {"correo": usuario.correo, "codigo": "codigo-falso",
                                                 "contrasena": pk.FRASE_NUEVA, "confirmacion": pk.FRASE_NUEVA}).status_code
    with mock.patch.object(limites.VERIFICACION, "limite", 2):
        limites.VERIFICACION.reiniciar()
        v = cliente(ip="203.0.113.79")
        verificaciones = [v.post("/verificar/", {"certificado": "{}"}).status_code for _ in range(3)]
    limites.VERIFICACION.reiniciar()
    ok = (fallos == [200] * 3 and bloqueada == 429 and falsificada == 429 and otra_ip == 302
          and canjes == [200] * 3 and canje_bloqueado == 429 and verificaciones == [200, 200, 429])
    return ok, (f"acceso {fallos}+{bloqueada}; XFF falsificado {falsificada}; otra IP {otra_ip};"
                f" recuperación {canjes}+{canje_bloqueado}; verificación {verificaciones}")


def i11():
    d = pa.Datos()
    ctx = d.finca()
    ctx["parcela"] = d.parcela(ctx)
    tecnico = d.usuario("R1")
    catalogo.asignar_tecnico(ctx["r3"], ctx["parcela"], tecnico.pk, hora_de_la_base() + timedelta(days=30))
    periodo = servicios.abrir_periodo(ctx["r7"], ps.INICIO, ps.FIN).periodo_id
    r = como(tecnico).post(ruta("O1.Rg", ctx["parcela"]), {
        "periodo_id": periodo, "co2e_toneladas": "100.000", "fecha_muestreo": "2026-01-15", "notas": NOTA_SCRIPT})
    d.actor(ctx["r7"])
    medicion = Medicion.objects.filter(parcela_id=ctx["parcela"]).values_list("pk", flat=True).get()
    cuerpo = texto(como(ctx["r7"]).get(f"/mediciones/{medicion}/"))
    ok = completada(r, "O1.Rg") and "&lt;script&gt;alert(1)&lt;/script&gt;" in cuerpo and NOTA_SCRIPT not in cuerpo
    return ok, f"registro {estado(r)}; escapada={'&lt;script&gt;' in cuerpo}; sin etiqueta cruda={NOTA_SCRIPT not in cuerpo}"


def i12():
    d = pa.Datos()
    ctx = d.base()
    with override_settings(BITACORA_URL=f"http://127.0.0.1:{pa.puerto_libre()}"):
        c = como(ctx["r7"])
        consulta = c.get("/bitacora/")
        lectura = c.get(f"/mediciones/{ctx['medicion']}/")
    cuerpos = texto(consulta) + texto(lectura)
    generica = ("no está disponible" in cuerpos and "Traceback" not in cuerpos and "127.0.0.1" not in cuerpos
                and "Cd17" not in cuerpos and "Bitacora" not in cuerpos)
    ok = consulta.status_code == 503 and lectura.status_code == 503 and generica
    return ok, f"bitácora {estado(consulta)}; lectura de R7 {estado(lectura)}; página genérica={generica}"


def i13():
    d = pa.Datos()
    r4 = d.usuario("R4")
    usuario, secreto = d.cuenta_con_totp(r4)
    c = cliente()
    iniciar_sesion(c, usuario, secreto)
    c.post("/salida/")
    d.sql("UPDATE usuarios_usuario SET last_login = now() - interval '1 hour' WHERE id = %s", [usuario.pk])
    cuentas.asignar_rol(d.usuario("R4"), usuario.pk, "R1")
    c = cliente()
    _, segundo = iniciar_sesion(c, usuario, secreto)
    primera = texto(c.get("/cuenta/"))
    recarga = texto(c.get("/cuenta/"))
    c.post("/salida/")
    c = cliente()
    iniciar_sesion(c, usuario, secreto)
    tercera = texto(c.get("/cuenta/"))
    aviso = "Se le asignó el rol R1"
    ok = segundo.status_code == 302 and aviso in primera and aviso not in recarga and aviso not in tercera
    return ok, f"aviso en el acceso siguiente={aviso in primera}; al recargar={aviso in recarga}; en el acceso posterior={aviso in tercera}"


def i14():
    """Acción crítica con segundo factor viejo: pide reautenticación, no reenvía el POST y muestra la
    operación para confirmarla."""
    d = pa.Datos()
    ctx = d.cerrada()
    verificador, secreto = d.cuenta_con_totp(d.usuario("R4"))
    d.dar_rol(verificador.pk, "R2")
    c = entrar(cliente(), verificador, edad=3600)
    r = c.post(ruta("O1.Ap", ctx["medicion"]), {"huella_revisada": ctx["huella"]})
    pide = r.status_code == 302 and r["Location"].startswith("/acceso/reautenticar/?next=")
    d.actor(ctx["r7"])
    sin_aprobar = Medicion.objects.filter(pk=ctx["medicion"]).values_list("estado", flat=True).get() == "presentada"
    reiniciar_totp(verificador)
    vuelta = c.post("/acceso/reautenticar/", {"codigo": totp.codigo_para(secreto, time.time()),
                                              "next": ruta("O1.Ap", ctx["medicion"])})
    confirmacion = c.get(vuelta["Location"]) if vuelta.status_code == 302 else vuelta
    pide_confirmar = "confirme la operación" in texto(confirmacion)
    aprobada = c.post(ruta("O1.Ap", ctx["medicion"]), {"huella_revisada": ctx["huella"]})
    ok = pide and sin_aprobar and vuelta.status_code == 302 and pide_confirmar and completada(aprobada, "O1.Ap")
    return ok, f"pide segundo factor={pide}; sin ejecutar={sin_aprobar}; confirmación={pide_confirmar}; luego {estado(aprobada)}"


# --------------------------------------------------------------------------- B1: humo con servidor real


class _ServidorCompartido(ThreadedWSGIServer):
    """Servidor HTTP real en loopback que usa la conexión de la prueba (dentro de su transacción
    revertida): no cierra conexiones al terminar cada petición."""

    def _close_connections(self):
        pass


class _HiloServidor(LiveServerThread):
    server_class = _ServidorCompartido

    def run(self):
        for alias, conexion in self.connections_override.items():
            connections[alias] = conexion
        try:
            self.httpd = self._create_server(connections_override=self.connections_override)
            self.port = self.httpd.server_address[1]
            self.httpd.set_app(WSGIHandler())
            self.is_ready.set()
            self.httpd.serve_forever()
        except Exception as error:
            self.error = error
            self.is_ready.set()


class _SinRedirecciones(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *argumentos, **opciones):
        return None


def _pedir(abridor, url: str, datos: dict | None = None):
    cuerpo = urllib.parse.urlencode(datos).encode() if datos is not None else None
    try:
        with abridor.open(urllib.request.Request(url, data=cuerpo), timeout=60) as r:
            return r.status, r.headers, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.headers, error.read().decode("utf-8", errors="replace")


def _token(html: str) -> str:
    encontrado = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
    return encontrado.group(1) if encontrado else ""


def b01():
    """Servidor HTTP real en 127.0.0.1 (puerto libre): acceso en dos pasos, una operación concedida,
    una denegada y la verificación pública, con peticiones por socket."""
    d = pa.Datos()
    usuario, secreto = d.cuenta_con_totp(d.usuario("R4"))
    d.dar_rol(usuario.pk, "R7")
    reiniciar_totp(usuario)
    real = connections["default"]
    real.inc_thread_sharing()
    request_started.disconnect(close_old_connections)
    request_finished.disconnect(close_old_connections)
    hilo = _HiloServidor("127.0.0.1", None, connections_override={"default": real}, port=0)
    hilo.daemon = True
    try:
        hilo.start()
        hilo.is_ready.wait()
        if hilo.error:
            raise hilo.error
        base = f"http://127.0.0.1:{hilo.port}"
        abridor = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                              _SinRedirecciones())
        _, _, pagina = _pedir(abridor, base + "/acceso/")
        paso1, _, _ = _pedir(abridor, base + "/acceso/", {"csrfmiddlewaretoken": _token(pagina), "correo": usuario.correo,
                                                         "password": pk.FRASE_LARGA})
        _, _, pagina = _pedir(abridor, base + "/acceso/segundo-factor/")
        paso2, cabeceras2, _ = _pedir(abridor, base + "/acceso/segundo-factor/", {
            "csrfmiddlewaretoken": _token(pagina), "codigo": totp.codigo_para(secreto, time.time())})
        cuenta, cabeceras, _ = _pedir(abridor, base + "/cuenta/")
        _, _, formulario = _pedir(abridor, base + ruta("O2.Ab"))
        concedida, _, cuerpo_c = _pedir(abridor, base + ruta("O2.Ab"), {
            "csrfmiddlewaretoken": _token(formulario), "inicio": ps.INICIO.isoformat(), "fin": ps.FIN.isoformat()})
        negada, _, cuerpo_n = _pedir(abridor, base + ruta("O1.MdC"), {"csrfmiddlewaretoken": _token(formulario)})
        publico = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        _, _, pagina = _pedir(publico, base + "/verificar/")
        documento = json.dumps(firma.firmar(firma.construir_payload(
            uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), 1, "123.400", "a" * 64, [uuid.uuid4()],
            hora_de_la_base())))
        verificada, _, cuerpo_v = _pedir(publico, base + "/verificar/", {"csrfmiddlewaretoken": _token(pagina),
                                                                         "certificado": documento})
    finally:
        if hilo.is_alive():
            hilo.terminate()
            hilo.join(timeout=10)
        request_started.connect(close_old_connections)
        request_finished.connect(close_old_connections)
        real.dec_thread_sharing()
    observado = {
        "acceso": (paso1, paso2, cuenta),
        "concedida": concedida == 200 and "Operación O2.Ab completada." in cuerpo_c,
        "denegada": negada == 403 and '<span class="regla">defecto</span>' in cuerpo_n,
        "verificacion": verificada == 200 and 'data-conclusion="integro_verdeazul"' in cuerpo_v,
        "encabezados": "frame-ancestors 'none'" in cabeceras.get("Content-Security-Policy", "")
                       and cabeceras.get("Cache-Control") == "no-store",
        "galleta": any(g.startswith("sessionid=") and "HttpOnly" in g and "SameSite=Lax" in g
                       for g in cabeceras2.get_all("Set-Cookie") or []),
    }
    ok = observado["acceso"] == (302, 302, 200) and all(v for k, v in observado.items() if k != "acceso")
    return ok, (f"acceso {observado['acceso']}; O2.Ab concedida={observado['concedida']}; O1.MdC 403 defecto="
                f"{observado['denegada']}; verificación íntegra={observado['verificacion']};"
                f" CSP y no-store={observado['encabezados']}; galleta HttpOnly y Lax={observado['galleta']}")


# --------------------------------------------------------------------------- ejecución


def conteos() -> dict[str, int]:
    totales = pa.conteos()
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT count(*) FROM {TABLA_INTENTOS}")
        totales[TABLA_INTENTOS] = cursor.fetchone()[0]
    return totales


def pruebas() -> list[tuple[str, str, str, object]]:
    lista = [
        ("I01", "Anónimo redirigido al acceso en cada ruta protegida", "302 a /acceso/?next=", i01),
        ("I02", "Acceso: contraseña mala genérica; TOTP malo y bueno; banderas de la galleta; next", "genérico; 302; Lax", i02),
        ("I03", "POST sin token CSRF en cada ruta POST", "403", i03),
    ]
    for clave in ESCRITURAS:
        lista.append((f"I04 {clave}", f"{registro.POR_CLAVE[clave].etiqueta} por HTTP", "concedida", caso_escritura(clave)))
    for codigo in LECTURAS:
        lista.append((f"I04 {codigo}", f"Lectura {codigo} por HTTP", "200", caso_lectura(codigo)))
    for codigo in DENEGADAS:
        lista.append((f"I04 {codigo}", f"{codigo}, denegada a todos", "403 defecto; registrada", caso_denegada(codigo)))
    lista += [
        ("I05", "Proyección: mismo objeto, distintos campos por rol; los excluidos no llegan", "distintos; ausentes", i05),
        ("I06", "R6 lee solo sus certificados", "propio sí; ajeno no; 403", i06),
        ("I07", "Verificación pública: íntegro propio, otra clave, alterado (un byte), formato", "4 conclusiones", i07),
        ("I08", "Exportación: adjunto, nosniff y SHA-256 en la bitácora", "SHA-256 registrada", i08),
        ("I09", "huella_revisada: la medición cambia entre mostrar y aprobar", "403 Cd7", i09),
        ("I10", "Límites por IP: acceso, recuperación y verificación", "429", i10),
        ("I11", "Nota con <script> sale escapada", "escapada", i11),
        ("I12", "Bitácora caída: lectura de R7 denegada con página genérica", "503 genérico", i12),
        ("I13", "Aviso al titular solo una vez", "una vez", i13),
        ("I14", "Acción crítica sin segundo factor reciente: reautenticación y confirmación", "302; confirmar", i14),
        ("B1", "Humo con servidor HTTP real en loopback: acceso, concedida, denegada, verificación", "todo observado", b01),
    ]
    return lista


def main() -> int:
    global INSTANCIA
    for flujo in (sys.stdout, sys.stderr):
        flujo.reconfigure(errors="replace")
    pb.logging.getLogger("verdeazul").setLevel(pb.logging.ERROR)
    pb.logging.getLogger("bitacora_svc").setLevel(pb.logging.ERROR)
    pb.logging.getLogger("django.request").setLevel(pb.logging.CRITICAL)
    nombre = f"{esquema.PREFIJO_PRUEBA}{uuid.uuid4().hex[:10]}"
    opa = None
    resultados = []
    try:
        INSTANCIA = pb.Instancia(nombre)
        ps.usar(ps.APP)
        iniciales = conteos()
        with override_settings(DEBUG=False, BITACORA_URL=INSTANCIA.url, ALLOWED_HOSTS=[HOST, "127.0.0.1"]):
            # Con argumentos (por ejemplo "I04 B1") corre solo las pruebas cuyo id empieza así, sin OPA.
            filtro = tuple(sys.argv[1:])
            for id_, descripcion, esperado, funcion in pruebas():
                if not filtro or id_.startswith(filtro):
                    resultados.append(ps.ejecutar(id_, descripcion, esperado, funcion))
            if not filtro and (RAIZ / ".opa_local.json").exists():
                opa, url = pa.iniciar_opa()
                with mock.patch.dict(os.environ, {"PDP_BACKEND": "opa", "OPA_URL": url}):
                    for clave in OPA_SUBCONJUNTO:
                        funcion = (caso_escritura(clave) if clave in ESCRITURAS else
                                   caso_lectura(clave) if clave in LECTURAS else caso_denegada(clave))
                        resultados.append(ps.ejecutar(f"I04 {clave} opa", f"{clave} con PDP OPA", "igual que python", funcion))
        finales = conteos()
        eventos = INSTANCIA.app.servicio.salud()["ultimo_seq"]
    finally:
        if opa is not None:
            opa.terminate()
            opa.wait(timeout=10)
        if INSTANCIA is not None:
            INSTANCIA.cerrar()
        ps.connections["default"].close()
    restantes = pb.esquemas_restantes([nombre])
    pm.imprimir_tabla(resultados)
    correctas = sum(r.ok for r in resultados)
    i04 = [r for r in resultados if r.id.startswith("I04") and not r.id.endswith("opa")]
    print(f"\nI04: {sum(r.ok for r in i04)}/{len(i04)} OK (24 escrituras en {len(ESCRITURAS)} combinaciones de operación y servicio, 8 lecturas, 9 denegadas)")
    print(f"Total: {correctas}/{len(resultados)} OK")
    print(f"Bitácora de prueba: {eventos} eventos; esquemas temporales restantes: {restantes}")
    limpio = finales == iniciales
    print(f"Conteos antes: {iniciales}")
    print(f"Conteos después: {finales}")
    print("[OK] No quedaron datos de prueba." if limpio and restantes == 0 else "[FALLO] Quedaron datos de prueba.")
    return 0 if correctas == len(resultados) and limpio and restantes == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
