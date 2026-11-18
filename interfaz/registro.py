"""Registro de las 41 operaciones de la matriz: lo que la interfaz presenta y cómo invoca cada una.

Cada entrada fija la operación, su etiqueta, el tipo del objeto (que sale de la URL), el servicio del
mapa del PEP, el formulario explícito y cómo se arman los argumentos. Las 8 lecturas llevan a sus
vistas de lectura; las 9 operaciones denegadas a todos pasan por el PEP y terminan en 403.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from autorizacion import motor
from interfaz import formularios as f

ESCRITURA = "escritura"
LECTURA = "lectura"
DENEGADA = "denegada"


@dataclass(frozen=True)
class Entrada:
    clave: str
    codigo: str
    etiqueta: str
    clase: str
    objeto: str = "ninguno"
    servicio: str | None = None
    formulario: type | None = None
    argumentos: Callable | None = None
    ruta_lectura: str | None = None

    @property
    def con_objeto(self) -> bool:
        return self.objeto != "ninguno"


def _e(clave, codigo, etiqueta, objeto, servicio, formulario, argumentos):
    return Entrada(clave, codigo, etiqueta, ESCRITURA, objeto, servicio, formulario, argumentos)


def _l(codigo, etiqueta, ruta):
    return Entrada(codigo, codigo, etiqueta, LECTURA, ruta_lectura=ruta)


def _d(codigo, etiqueta):
    return Entrada(codigo, codigo, etiqueta, DENEGADA)


ENTRADAS = [
    _l("O1.L", "Leer mediciones", "lista_mediciones"),
    _e("O1.Rg", "O1.Rg", "Registrar medición", "parcela", "registrar_medicion", f.RegistrarMedicion,
       lambda d, o: {"parcela_id": o, "periodo_id": d["periodo_id"], "co2e_toneladas": d["co2e_toneladas"],
                     "fecha_muestreo": d["fecha_muestreo"], "notas": d["notas"] or None}),
    _e("O1.Md", "O1.Md", "Modificar medición en borrador", "medicion", "modificar_medicion", f.ModificarMedicion,
       lambda d, o: {"medicion_id": o, "co2e_toneladas": d["co2e_toneladas"], "fecha_muestreo": d["fecha_muestreo"],
                     "notas": d["notas"] or None}),
    _e("O1.Pr", "O1.Pr", "Presentar medición", "medicion", "presentar_medicion", f.Confirmacion,
       lambda d, o: {"medicion_id": o}),
    _e("O1.Ap", "O1.Ap", "Aprobar medición", "medicion", "aprobar_medicion", f.Revision,
       lambda d, o: {"medicion_id": o, "huella_revisada": d["huella_revisada"]}),
    _e("O1.Dv", "O1.Dv", "Devolver medición", "medicion", "devolver_medicion", f.Revision,
       lambda d, o: {"medicion_id": o, "huella_revisada": d["huella_revisada"]}),
    _e("O1.Rs", "O1.Rs", "Reasignar verificación", "medicion", "reasignar_verificacion", f.Reasignar,
       lambda d, o: {"medicion_id": o, "destino_id": d["destino_id"]}),
    _d("O1.MdC", "Modificar medición certificada"),
    _d("O1.El", "Eliminar medición"),
    _l("O2.L", "Leer períodos", "lista_periodos"),
    _e("O2.Ab", "O2.Ab", "Abrir período", "ninguno", "abrir_periodo", f.AbrirPeriodo,
       lambda d, o: {"inicio": d["inicio"], "fin": d["fin"]}),
    _e("O2.Ci", "O2.Ci", "Cerrar período", "periodo", "cerrar_periodo", f.Confirmacion,
       lambda d, o: {"periodo_id": o}),
    _d("O2.Ro", "Reabrir período"),
    _l("O3.L", "Leer certificados", "lista_certificados"),
    _e("O3.An", "O3.An", "Anular certificado", "certificado", "anular_certificado", f.Justificacion,
       lambda d, o: {"certificado_id": o, "justificacion": d["justificacion"]}),
    _e("O3.Ex", "O3.Ex", "Exportar certificado", "certificado", "exportar_certificado", f.Confirmacion,
       lambda d, o: {"certificado_id": o}),
    _d("O3.El", "Eliminar certificado"),
    _l("O4.L", "Leer enmiendas", "lista_enmiendas"),
    _e("O4.So", "O4.So", "Solicitar enmienda", "medicion", "solicitar_enmienda", f.SolicitarEnmienda,
       lambda d, o: {"medicion_id": o, "motivo": d["motivo"], "co2e_nuevo": d["co2e_nuevo"],
                     "fecha_nueva": d["fecha_nueva"], "notas_nuevas": d["notas_nuevas"] or None}),
    _e("O4.Au", "O4.Au", "Resolver enmienda", "enmienda", "resolver_enmienda", f.ResolverEnmienda,
       lambda d, o: {"enmienda_id": o, "autorizar": d["decision"] == "autorizar"}),
    _d("O4.El", "Eliminar enmienda"),
    _l("O5.L", "Leer catálogo de fincas y parcelas", "lista_parcelas"),
    _e("O5.Cr-finca", "O5.Cr", "Crear finca", "ninguno", "crear_finca", f.CrearFinca,
       lambda d, o: {"nombre": d["nombre"], "propietarios": d["propietarios"]}),
    _e("O5.Cr-parcela", "O5.Cr", "Crear parcela", "finca", "crear_parcela", f.CrearParcela,
       lambda d, o: {"finca_id": o, "codigo": d["codigo"], "wkt": d["wkt"]}),
    _e("O5.Md-parcela", "O5.Md", "Modificar parcela", "parcela", "modificar_parcela", f.ModificarParcela,
       lambda d, o: {"parcela_id": o, "codigo": d["codigo"] or None, "wkt": d["wkt"] or None}),
    _e("O5.Md-propietarios", "O5.Md", "Cambiar propietarios de finca", "finca", "cambiar_propietarios",
       f.CambiarPropietarios, lambda d, o: {"finca_id": o, "agregar": d["agregar"] or (), "retirar": d["retirar"] or ()}),
    _e("O5.As", "O5.As", "Asignar técnico", "parcela", "asignar_tecnico", f.AsignarTecnico,
       lambda d, o: {"parcela_id": o, "tecnico_id": d["tecnico_id"], "vence_en": d["vence_en"]}),
    _e("O5.Ba", "O5.Ba", "Dar de baja parcela", "parcela", "dar_de_baja_parcela", f.Confirmacion,
       lambda d, o: {"parcela_id": o}),
    _d("O5.El", "Eliminar del catálogo"),
    _l("O6.L", "Leer cuentas y roles", "lista_cuentas"),
    _e("O6.Al", "O6.Al", "Alta de cuenta", "ninguno", "alta_cuenta", f.AltaCuenta,
       lambda d, o: {"correo": d["correo"], "nombre": d["nombre"]}),
    _e("O6.Md-cuenta", "O6.Md", "Modificar cuenta", "cuenta", "modificar_cuenta", f.ModificarCuenta,
       lambda d, o: {"usuario_id": o, "nombre": d["nombre"]}),
    _e("O6.Md-recuperacion", "O6.Md", "Emitir código de recuperación", "cuenta", "emitir_recuperacion",
       f.Confirmacion, lambda d, o: {"usuario_id": o}),
    _e("O6.AR-asignar", "O6.AR", "Asignar rol", "cuenta", "asignar_rol", f.Rol,
       lambda d, o: {"usuario_id": o, "rol": d["rol"]}),
    _e("O6.AR-revocar", "O6.AR", "Revocar rol", "cuenta", "revocar_rol", f.Rol,
       lambda d, o: {"usuario_id": o, "rol": d["rol"]}),
    _e("O6.Ba", "O6.Ba", "Dar de baja cuenta", "cuenta", "dar_de_baja_cuenta", f.Confirmacion,
       lambda d, o: {"usuario_id": o}),
    _e("O6.Sv", "O6.Sv", "Solicitar ventana de auditoría", "cuenta", "solicitar_ventana", f.SolicitarVentana,
       lambda d, o: {"auditor_id": o, "inicio": d["inicio"], "fin": d["fin"]}),
    _e("O6.Av", "O6.Av", "Abrir ventana de auditoría", "ventana", "abrir_ventana", f.Confirmacion,
       lambda d, o: {"ventana_id": o}),
    _e("O6.Ae", "O6.Ae", "Autorizar acceso de emergencia", "cuenta", "autorizar_emergencia", f.AutorizarEmergencia,
       lambda d, o: {"beneficiario_id": o, "rol_suplido": d["rol_suplido"]}),
    _l("O7.L", "Consultar bitácora", "bitacora"),
    _d("O7.Es", "Escribir en la bitácora"),
    _d("O7.MdE", "Modificar un evento de la bitácora"),
    _l("O8.L", "Leer alertas", "lista_alertas"),
    _e("O8.Rs", "O8.Rs", "Resolver alerta", "alerta", "resolver_alerta", f.Justificacion,
       lambda d, o: {"alerta_id": o, "justificacion": d["justificacion"]}),
    _d("O8.Cf", "Configurar alertas"),
]

POR_CLAVE = {e.clave: e for e in ENTRADAS}
CODIGOS = sorted({e.codigo for e in ENTRADAS})


def entradas_de(codigo: str) -> list[Entrada]:
    return [e for e in ENTRADAS if e.codigo == codigo]


def codigos_de_roles(roles) -> list[str]:
    """Operaciones que la matriz da a alguno de los roles (solo para presentar la consola)."""
    operaciones = motor.matriz()["operaciones"]
    return [codigo for codigo in operaciones if any(rol in operaciones[codigo] for rol in roles)]
