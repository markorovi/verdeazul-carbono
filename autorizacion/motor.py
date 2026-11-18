"""Motor de decisión de referencia en Python, con el mismo contrato y la misma matriz que la política
Rego (policy/autorizacion.rego). Sirve como backend seleccionable (PDP_BACKEND=python) y como
oráculo de paridad: ante la misma entrada ambos devuelven la misma decisión.

Composición: denegación por defecto; deny-overrides (Cd9 duro, Cd17 sin bitácora y exportación con
H2 degradado anulan cualquier permiso); se concede si algún rol del sujeto tiene la operación con
todas sus condiciones de política verdaderas. Las condiciones de servicio no se evalúan aquí: se
devuelven en condiciones_servicio para que el PEP compruebe que el servicio las aplica.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

RUTA = Path(__file__).resolve().parent
DEFECTO = "defecto"
RESTRICCION_2FA = "2fa_reciente"
RESTRICCION_AVISO = "aviso_r7"
RESTRICCION_CERRAR = "cerrar_sesion"
OPERACION_EXPORTAR = "O3.Ex"

H2_OK = "ok"
H2_BLANDO = "blando"
H2_DURO = "duro"
H2_DENEGADO = "denegado"
PARAMETROS_H2 = (
    "h2_wc_laboral_blando",
    "h2_wc_laboral_duro",
    "h2_wc_fuera_blando",
    "h2_wc_fuera_duro",
    "h2_wl_blando",
    "h2_wl_duro",
)

# Hecho del PIP que decide cada condición de política (Cd9 se decide con estado_h2).
HECHOS = {
    "Cd1": "asignacion_vigente",
    "Cd2": "propietario",
    "Cd3": "ventana_vigente",
    "Cd4": "segundo_factor",
    "Cd16": "proyeccion_disponible",
    "Cd17": "bitacora_disponible",
    "Cd21": "estado_visible_r2",
    "Cd22": "misma_region",
}


@lru_cache(maxsize=1)
def matriz() -> dict:
    return json.loads((RUTA / "matriz.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def politica() -> dict:
    return json.loads((RUTA / "politica.json").read_text(encoding="utf-8"))


def objeto_de(operacion: str) -> str:
    return operacion.split(".", 1)[0]


def tipo_de(operacion: str) -> str:
    return operacion.split(".", 1)[1]


def _es_numero(valor) -> bool:
    return isinstance(valor, (int, float)) and not isinstance(valor, bool)


def estado_h2(h2, parametros) -> str:
    """Cd9 (H2): ok, blando (concede con restricciones), duro (deniega y cierra sesión) o denegado.

    Sin contadores disponibles falla degradado: concede solo lo que no es ajeno. Si falta un
    umbral o un contador, deniega.
    """
    if not isinstance(h2, dict):
        return H2_DENEGADO
    if h2.get("disponible") is not True:
        return H2_OK if h2.get("ajena") is False else H2_DENEGADO
    if not all(_es_numero(parametros.get(p)) for p in PARAMETROS_H2):
        return H2_DENEGADO
    if not (_es_numero(h2.get("wc")) and _es_numero(h2.get("wl"))):
        return H2_DENEGADO
    franja = "laboral" if h2.get("laboral") is True else "fuera"
    wc, wl = h2["wc"], h2["wl"]
    if wc >= parametros[f"h2_wc_{franja}_duro"] or wl >= parametros["h2_wl_duro"]:
        return H2_DURO
    if wc >= parametros[f"h2_wc_{franja}_blando"] or wl >= parametros["h2_wl_blando"]:
        return H2_BLANDO
    return H2_OK


def _cumple(condicion: str, hechos: dict, h2: str) -> bool:
    if condicion == "Cd9":
        return h2 in (H2_OK, H2_BLANDO)
    return hechos.get(HECHOS[condicion]) is True


def denegar(razon: str, restricciones=()) -> dict:
    return {
        "permitir": False,
        "razon": razon,
        "restricciones": list(restricciones),
        "condiciones_servicio": [],
        "proyeccion": None,
        "registrar_lectura": False,
    }


def _conceder(operacion: str, condiciones: list, rol: str, h2: str) -> dict:
    p = politica()
    restricciones = set()
    if "Cd4" in condiciones and operacion in p["operaciones_criticas"]:
        restricciones.add(RESTRICCION_2FA)
    if "Cd9" in condiciones and h2 == H2_BLANDO:
        restricciones.update({RESTRICCION_2FA, RESTRICCION_AVISO})
    servicio = set(matriz()["condiciones_servicio"])
    if "Cd16" in condiciones:
        proyeccion = p["proyecciones"].get(rol)
    else:
        proyeccion = p["proyecciones_por_operacion"].get(operacion, {}).get(rol)
    return {
        "permitir": True,
        "razon": None,
        "restricciones": sorted(restricciones),
        "condiciones_servicio": [c for c in condiciones if c in servicio],
        "proyeccion": proyeccion,
        "registrar_lectura": "Cd17" in condiciones,
    }


def _emergencia_prohibida(operacion: str, emergencia: dict) -> bool:
    p = politica()
    return (
        emergencia.get("rol_suplido") not in p["roles_suplibles"]
        or tipo_de(operacion) != "L"
        or objeto_de(operacion) not in p["objetos_emergencia"]
    )


def evento_visible(proyeccion: str | None, evento: dict) -> bool:
    """Visibilidad de un evento de bitácora bajo una proyección (misma regla que el Rego).

    Sin proyección se ve todo (el auditor, dentro de su ventana). Con bitacora_r7, R7 ve la clase
    certificación y la administración de cuentas, roles, ventanas, emergencia y alertas (O6 y O8);
    nunca los accesos (autenticación y denegaciones) ni el detalle de lecturas.
    """
    if proyeccion is None:
        return True
    regla = politica()["visibilidad_bitacora"].get(proyeccion)
    if regla is None:
        return False
    if evento.get("clase") in regla["clases"]:
        return True
    operacion = evento.get("operacion") or ""
    return evento.get("clase") == "administracion" and operacion.split(".", 1)[0] in regla["administracion_objetos"]


def decidir(entrada: dict) -> dict:
    operacion = entrada.get("operacion")
    sujeto = entrada.get("sujeto") or {}
    hechos = entrada.get("hechos") or {}
    parametros = entrada.get("parametros") or {}
    permisos = matriz()["operaciones"].get(operacion)
    if not permisos:
        return denegar(DEFECTO)
    emergencia = sujeto.get("emergencia")
    if emergencia is not None:
        if not isinstance(emergencia, dict) or _emergencia_prohibida(operacion, emergencia):
            return denegar("Cd24")
        roles = [emergencia["rol_suplido"]]
    else:
        roles = sorted(set(sujeto.get("roles") or []))
    candidatos = [r for r in roles if r in permisos]
    if not candidatos:
        return denegar(DEFECTO)
    h2 = estado_h2(hechos.get("h2"), parametros)
    if h2 == H2_DURO and any("Cd9" in permisos[r] for r in candidatos):
        return denegar("Cd9", [RESTRICCION_CERRAR])
    if hechos.get("bitacora_disponible") is not True and any("Cd17" in permisos[r] for r in candidatos):
        return denegar("Cd17")
    if operacion == OPERACION_EXPORTAR and not (isinstance(hechos.get("h2"), dict) and hechos["h2"].get("disponible") is True):
        return denegar("Cd9")
    de_politica = set(matriz()["condiciones_politica"])
    fallidas = {
        r: [c for c in permisos[r] if c in de_politica and not _cumple(c, hechos, h2)] for r in candidatos
    }
    for rol in candidatos:
        if not fallidas[rol]:
            return _conceder(operacion, permisos[rol], rol, h2)
    return denegar(fallidas[candidatos[0]][0])
