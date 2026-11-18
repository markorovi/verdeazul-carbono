"""Serializadores explícitos por objeto y por proyección (Cd16).

La proyección la decide la política ("tecnico", "auditor", "dueno", "bitacora_r7" o ninguna, que
aquí es "completa"). Cada objeto declara los campos de cada proyección; solo se calculan y se
entregan esos campos, así que un campo fuera de la proyección ni siquiera llega al contexto de la
plantilla. Una proyección que el objeto no declara deniega (Cd16). Las personas aparecen solo como
seudónimo (16 hex), salvo en la ficha completa de una cuenta (O6.L de R4 y R7).

Se llaman dentro de la transacción con el actor declarado: la RLS de la base sigue aplicando.
"""

from __future__ import annotations

from dataclasses import dataclass

from autorizacion import pep
from catalogo.models import Finca, Parcela, Propiedad
from mediciones import firma
from mediciones.models import Alerta, Certificado, Enmienda, Medicion, MedicionVersion, Periodo
from usuarios.models import RolUsuario, Usuario

COMPLETA = "completa"


class ProyeccionNoDisponible(Exception):
    """La política pidió una proyección que el objeto no declara: se deniega por Cd16."""


@dataclass(frozen=True)
class Ficha:
    """Campos ya proyectados: (clave, etiqueta, valor como texto)."""

    tipo: str
    objeto_id: str | None
    campos: tuple

    def claves(self) -> set:
        return {clave for clave, _, _ in self.campos}


ETIQUETAS = {
    "id": "Identificador", "parcela": "Parcela", "periodo": "Período", "estado": "Estado", "ciclo": "Ciclo",
    "version": "Versión", "co2e_toneladas": "CO2e (t)", "fecha_muestreo": "Fecha de muestreo", "notas": "Notas",
    "huella": "Huella", "registrada_por": "Registrada por", "creada_en": "Creada en", "inicio": "Inicio",
    "fin": "Fin", "cerrado_en": "Cerrado en", "medicion": "Medición", "emitido_en": "Emitido en",
    "huella_medicion": "Huella de la medición", "aprobadores": "Aprobadores", "key_id": "Clave de firma",
    "anulado_en": "Anulado en", "justificacion_anulacion": "Justificación de la anulación",
    "solicitante": "Solicitante", "motivo": "Motivo", "co2e_nuevo": "CO2e nuevo (t)", "fecha_nueva": "Fecha nueva",
    "notas_nuevas": "Notas nuevas", "solicitada_en": "Solicitada en", "autorizador": "Autorizador",
    "resuelta_en": "Resuelta en", "codigo": "Código", "finca": "Finca", "finca_nombre": "Nombre de la finca",
    "dada_de_baja_en": "Dada de baja en", "nombre": "Nombre", "propietarios": "Propietarios",
    "correo": "Correo", "activo": "Activa", "creado_en": "Creada en", "roles": "Roles vigentes",
    "seudonimo": "Seudónimo", "tipo": "Tipo", "prioridad": "Prioridad", "usuario": "Originada por",
    "cuenta_afectada": "Cuenta afectada", "seq": "Secuencia", "sello": "Sello", "clase": "Clase",
    "accion": "Acción", "operacion": "Operación", "servicio": "Servicio", "objeto_tipo": "Tipo de objeto",
    "objeto_id": "Objeto", "decision": "Decisión", "regla": "Regla", "resultado": "Resultado",
}

PROYECCIONES = {
    "medicion": {
        COMPLETA: ("id", "parcela", "periodo", "estado", "ciclo", "version", "co2e_toneladas", "fecha_muestreo",
                   "notas", "huella", "registrada_por", "creada_en"),
        "dueno": ("id", "parcela", "periodo", "estado", "co2e_toneladas", "fecha_muestreo"),
    },
    "periodo": {
        COMPLETA: ("id", "inicio", "fin", "estado", "cerrado_en"),
    },
    "certificado": {
        COMPLETA: ("id", "parcela", "periodo", "medicion", "estado", "ciclo", "emitido_en", "co2e_toneladas",
                   "huella_medicion", "aprobadores", "key_id", "anulado_en", "justificacion_anulacion"),
        "tecnico": ("id", "parcela", "periodo", "medicion", "estado", "emitido_en", "co2e_toneladas", "huella_medicion"),
        "dueno": ("id", "parcela", "periodo", "estado", "emitido_en", "co2e_toneladas", "key_id"),
    },
    "enmienda": {
        COMPLETA: ("id", "medicion", "estado", "solicitante", "motivo", "co2e_nuevo", "fecha_nueva", "notas_nuevas",
                   "solicitada_en", "autorizador", "resuelta_en"),
        "dueno": ("id", "medicion", "estado", "co2e_nuevo", "fecha_nueva", "solicitada_en", "resuelta_en"),
    },
    "parcela": {
        COMPLETA: ("id", "codigo", "finca", "finca_nombre", "dada_de_baja_en"),
        "auditor": ("id", "codigo", "finca", "dada_de_baja_en"),
    },
    "finca": {
        COMPLETA: ("id", "nombre", "creada_en", "dada_de_baja_en", "propietarios"),
        "auditor": ("id", "nombre", "dada_de_baja_en"),
    },
    "cuenta": {
        COMPLETA: ("id", "correo", "nombre", "activo", "creado_en", "roles"),
        "auditor": ("seudonimo", "activo", "creado_en", "roles"),
    },
    "alerta": {
        COMPLETA: ("id", "tipo", "prioridad", "creada_en", "resuelta_en", "usuario", "cuenta_afectada", "parcela",
                   "medicion"),
    },
    "evento": {
        COMPLETA: ("seq", "sello", "clase", "accion", "operacion", "servicio", "objeto_tipo", "objeto_id", "decision",
                   "regla", "resultado", "usuario"),
        "bitacora_r7": ("seq", "sello", "clase", "accion", "operacion", "servicio", "objeto_tipo", "objeto_id",
                        "decision", "regla", "resultado", "usuario"),
    },
}


def campos_de(tipo: str, proyeccion: str | None) -> tuple:
    nombre = proyeccion or COMPLETA
    campos = PROYECCIONES.get(tipo, {}).get(nombre)
    if campos is None:
        raise ProyeccionNoDisponible(f"{tipo}:{nombre}")
    return campos


def _texto(valor) -> str:
    if valor is None:
        return ""
    if isinstance(valor, bool):
        return "sí" if valor else "no"
    if isinstance(valor, (list, tuple)):
        return ", ".join(_texto(v) for v in valor)
    if hasattr(valor, "isoformat"):
        return valor.isoformat()
    return str(valor)


def _seudonimo(usuario_id) -> str | None:
    return firma.seudonimo(usuario_id) if usuario_id else None


def _ficha(tipo: str, objeto_id, proyeccion, valores: dict) -> Ficha:
    """`valores` mapea cada campo a una función sin argumentos; solo se evalúan los proyectados."""
    campos = tuple((c, ETIQUETAS[c], _texto(valores[c]())) for c in campos_de(tipo, proyeccion))
    expuesto = str(objeto_id) if objeto_id is not None and "id" in campos_de(tipo, proyeccion) else None
    return Ficha(tipo, expuesto, campos)


def medicion(medicion_id, proyeccion) -> Ficha | None:
    m = Medicion.objects.filter(pk=medicion_id).first()
    if m is None:
        return None
    v = MedicionVersion.objects.filter(medicion_id=m.pk).order_by("-numero").first()
    return _ficha("medicion", m.pk, proyeccion, {
        "id": lambda: m.pk, "parcela": lambda: m.parcela_id, "periodo": lambda: m.periodo_id,
        "estado": lambda: m.estado, "ciclo": lambda: m.ciclo, "version": lambda: v.numero if v else None,
        "co2e_toneladas": lambda: v.co2e_toneladas if v else None,
        "fecha_muestreo": lambda: v.fecha_muestreo if v else None, "notas": lambda: v.notas if v else None,
        "huella": lambda: v.huella if v else None, "registrada_por": lambda: _seudonimo(m.registrada_por_id),
        "creada_en": lambda: m.creada_en,
    })


def huella_vigente(medicion_id) -> str | None:
    """Huella de la versión vigente: la que el verificador revisa (huella_revisada, Cd7)."""
    return (MedicionVersion.objects.filter(medicion_id=medicion_id).order_by("-numero")
            .values_list("huella", flat=True).first())


def periodo(periodo_id, proyeccion) -> Ficha | None:
    p = Periodo.objects.filter(pk=periodo_id).first()
    if p is None:
        return None
    return _ficha("periodo", p.pk, proyeccion, {
        "id": lambda: p.pk, "inicio": lambda: p.inicio, "fin": lambda: p.fin, "estado": lambda: p.estado,
        "cerrado_en": lambda: p.cerrado_en,
    })


def certificado(certificado_id, proyeccion) -> Ficha | None:
    c = Certificado.objects.filter(pk=certificado_id).first()
    if c is None:
        return None
    carga = c.payload if isinstance(c.payload, dict) else {}
    return _ficha("certificado", c.pk, proyeccion, {
        "id": lambda: c.pk, "parcela": lambda: c.parcela_id, "periodo": lambda: c.periodo_id,
        "medicion": lambda: c.medicion_id, "estado": lambda: c.estado, "ciclo": lambda: c.ciclo,
        "emitido_en": lambda: c.emitido_en, "co2e_toneladas": lambda: carga.get("co2e_toneladas"),
        "huella_medicion": lambda: carga.get("huella_medicion"), "aprobadores": lambda: carga.get("aprobadores"),
        "key_id": lambda: c.key_id, "anulado_en": lambda: c.anulado_en,
        "justificacion_anulacion": lambda: c.justificacion_anulacion,
    })


def enmienda(enmienda_id, proyeccion) -> Ficha | None:
    e = Enmienda.objects.filter(pk=enmienda_id).first()
    if e is None:
        return None
    return _ficha("enmienda", e.pk, proyeccion, {
        "id": lambda: e.pk, "medicion": lambda: e.medicion_id, "estado": lambda: e.estado,
        "solicitante": lambda: _seudonimo(e.solicitante_id), "motivo": lambda: e.motivo,
        "co2e_nuevo": lambda: e.co2e_nuevo, "fecha_nueva": lambda: e.fecha_nueva,
        "notas_nuevas": lambda: e.notas_nuevas, "solicitada_en": lambda: e.solicitada_en,
        "autorizador": lambda: _seudonimo(e.autorizador_id), "resuelta_en": lambda: e.resuelta_en,
    })


def parcela(parcela_id, proyeccion) -> Ficha | None:
    p = Parcela.objects.filter(pk=parcela_id).select_related("finca").first()
    if p is None:
        return None
    return _ficha("parcela", p.pk, proyeccion, {
        "id": lambda: p.pk, "codigo": lambda: p.codigo, "finca": lambda: p.finca_id,
        "finca_nombre": lambda: p.finca.nombre, "dada_de_baja_en": lambda: p.dada_de_baja_en,
    })


def finca(finca_id, proyeccion) -> Ficha | None:
    f = Finca.objects.filter(pk=finca_id).first()
    if f is None:
        return None
    return _ficha("finca", f.pk, proyeccion, {
        "id": lambda: f.pk, "nombre": lambda: f.nombre, "creada_en": lambda: f.creada_en,
        "dada_de_baja_en": lambda: f.dada_de_baja_en,
        "propietarios": lambda: sorted(_seudonimo(d) for d in Propiedad.objects.filter(
            finca_id=f.pk, hasta__isnull=True).values_list("dueno_id", flat=True)),
    })


def cuenta(usuario_id, proyeccion) -> Ficha | None:
    u = Usuario.objects.filter(pk=usuario_id).only("id", "correo", "nombre", "activo", "creado_en").first()
    if u is None:
        return None
    return _ficha("cuenta", u.pk, proyeccion, {
        "id": lambda: u.pk, "correo": lambda: u.correo, "nombre": lambda: u.nombre, "activo": lambda: u.activo,
        "creado_en": lambda: u.creado_en, "seudonimo": lambda: _seudonimo(u.pk),
        "roles": lambda: sorted(RolUsuario.objects.filter(usuario_id=u.pk, hasta__isnull=True)
                                .values_list("rol_id", flat=True)),
    })


def alerta(alerta_id, proyeccion) -> Ficha | None:
    a = Alerta.objects.filter(pk=alerta_id).first()
    if a is None:
        return None
    return _ficha("alerta", a.pk, proyeccion, {
        "id": lambda: a.pk, "tipo": lambda: a.tipo, "prioridad": lambda: a.prioridad,
        "creada_en": lambda: a.creada_en, "resuelta_en": lambda: a.resuelta_en,
        "usuario": lambda: _seudonimo(a.usuario_id), "cuenta_afectada": lambda: _seudonimo(a.cuenta_afectada_id),
        "parcela": lambda: a.parcela_id, "medicion": lambda: a.medicion_id,
    })


def evento(datos: dict, proyeccion) -> Ficha:
    """Evento de la bitácora tal como lo devuelve el servicio (ya seudonimizado y filtrado)."""
    return _ficha("evento", None, proyeccion, {campo: (lambda c=campo: datos.get(c)) for campo in PROYECCIONES["evento"][COMPLETA]})


POR_TIPO = {
    "medicion": medicion, "periodo": periodo, "certificado": certificado, "enmienda": enmienda,
    "parcela": parcela, "finca": finca, "cuenta": cuenta, "alerta": alerta,
}


def denegacion_cd16() -> pep.Denegado:
    return pep.Denegado("Cd16", "proyección no declarada por el serializador")
