"""PEP: punto de aplicación de la autorización.

Orden: autenticación, perfil de emergencia, PIP, PDP (RBAC, ABAC y H2) y servicio; denegación por
defecto y deny-overrides en la política. Todo lo que falle deniega (PIP, PDP, bitácora, registro
del intento), salvo Cd9, que falla degradado en la política.

- decidir() resuelve lecturas (operaciones L) y decisiones puras; registra cada intento de lectura
  en autorizacion_registroacceso, de donde salen los contadores de H2.
- ejecutar() resuelve una operación de escritura y, si se concede, invoca el servicio del mapa.
  Las condiciones de servicio (Cd5, Cd6, ...) las aplica el servicio: el PEP solo comprueba que el
  servicio invocado declare aplicar las que la decisión exige.

El cliente nunca ve la condición de una denegación: Denegado.publico() es un mensaje genérico; la
condición queda en el resultado interno y en el evento de bitácora.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

from django.core.exceptions import ImproperlyConfigured
from django.db import transaction

from autorizacion import motor, pip
from autorizacion.bitacora import Bitacora, bitacora_configurada
from autorizacion.models import RegistroAcceso
from autorizacion.pdp import pdp_configurado
from mediciones import alertas, firma
from mediciones.contexto import como_actor
from mediciones.errores import NoEncontrado, ReglaIncumplida
from mediciones.models import Alerta
from mediciones.transaccion import hora_de_la_base
from usuarios import autenticacion
from usuarios.models import RolUsuario

DEFECTO = motor.DEFECTO
MENSAJE_GENERICO = "No tiene permiso para realizar esta operación."
NIVEL_SIN_SESION = 0
NIVEL_CONTRASENA = 1
NIVEL_SEGUNDO_FACTOR = 2
CLAVE_EMERGENCIA = "emergencia"
TIPO_H2_UMBRAL_BLANDO = "h2_umbral_blando"
TIPO_DENEGACIONES_CD2 = "denegaciones_cd2"
DENEGACIONES_CD2_PARA_ALERTA = 3
VENTANA_AVISOS = timedelta(hours=24)


class ReautenticacionRequerida(Exception):
    """La operación se concede, pero exige un segundo factor reciente. No es una denegación."""


# --------------------------------------------------------------------------- sesión


@dataclass
class Sesion:
    usuario: object = None
    nivel_autenticacion: int = NIVEL_SIN_SESION
    # Instante (time.time()) del último segundo factor completado.
    segundo_factor_en: float | None = None
    # Perfil de emergencia ya consumido: {"rol_suplido": "R2", "vence_en": ISO 8601}.
    emergencia: dict | None = None

    def con_segundo_factor(self) -> bool:
        return self.usuario is not None and self.nivel_autenticacion >= NIVEL_SEGUNDO_FACTOR

    def segundo_factor_reciente(self) -> bool:
        if not self.con_segundo_factor() or not isinstance(self.segundo_factor_en, (int, float)):
            return False
        return 0 <= time.time() - self.segundo_factor_en <= motor.politica()["mfa_reciente_segundos"]


def sesion_desde_request(request) -> Sesion:
    """Lee las claves reales del módulo de autenticación. En este proyecto el inicio de sesión solo
    ocurre después del código TOTP, así que una sesión autenticada tiene segundo factor."""
    datos = getattr(request, "session", {}) or {}
    usuario = getattr(request, "user", None)
    if usuario is not None and getattr(usuario, "is_authenticated", False) and getattr(usuario, "is_active", False):
        momento = datos.get(autenticacion.CLAVE_MFA)
        con_mfa = isinstance(momento, (int, float))
        emergencia = datos.get(CLAVE_EMERGENCIA)
        return Sesion(
            usuario=usuario,
            nivel_autenticacion=NIVEL_SEGUNDO_FACTOR if con_mfa else NIVEL_CONTRASENA,
            segundo_factor_en=momento if con_mfa else None,
            emergencia=emergencia if isinstance(emergencia, dict) else None,
        )
    if datos.get(autenticacion.CLAVE_PRE_AUTH):
        return Sesion(nivel_autenticacion=NIVEL_CONTRASENA)
    return Sesion()


def guardar_emergencia(request, sesion: Sesion) -> None:
    if sesion.emergencia:
        request.session[CLAVE_EMERGENCIA] = sesion.emergencia
    else:
        request.session.pop(CLAVE_EMERGENCIA, None)


# --------------------------------------------------------------------------- resultados


@dataclass(frozen=True)
class Concedido:
    decision: dict
    resultado: object = None

    @property
    def permitido(self) -> bool:
        return True


@dataclass(frozen=True)
class Denegado:
    condicion: str
    motivo: str = ""

    @property
    def permitido(self) -> bool:
        return False

    def publico(self) -> dict:
        return {"permitido": False, "mensaje": MENSAJE_GENERICO}


# --------------------------------------------------------------------------- mapa de servicios


@lru_cache(maxsize=1)
def servicios() -> dict:
    """Operación -> {nombre del servicio: (función, condiciones de servicio que aplica)}."""
    from catalogo import servicios as cat
    from mediciones import servicios as med
    from usuarios import servicios as cue

    return {
        "O1.Rg": {"registrar_medicion": (med.registrar_medicion, {"Cd5"})},
        "O1.Md": {"modificar_medicion": (med.modificar_medicion, {"Cd5", "Cd6"})},
        "O1.Pr": {"presentar_medicion": (med.presentar_medicion, {"Cd5", "Cd6"})},
        "O1.Ap": {"aprobar_medicion": (med.aprobar_medicion, {"Cd7", "Cd8", "Cd10"})},
        "O1.Dv": {"devolver_medicion": (med.devolver_medicion, {"Cd7", "Cd8"})},
        "O1.Rs": {"reasignar_verificacion": (med.reasignar_verificacion, {"Cd8", "Cd19"})},
        "O2.Ab": {"abrir_periodo": (med.abrir_periodo, set())},
        "O2.Ci": {"cerrar_periodo": (med.cerrar_periodo, {"Cd5"})},
        "O3.An": {"anular_certificado": (med.anular_certificado, {"Cd20"})},
        "O3.Ex": {"exportar_certificado": (med.exportar_certificado, set())},
        "O4.So": {"solicitar_enmienda": (med.solicitar_enmienda, {"Cd11"})},
        "O4.Au": {"resolver_enmienda": (med.resolver_enmienda, {"Cd12"})},
        "O5.Cr": {
            "crear_finca": (cat.crear_finca, {"Cd14"}),
            "crear_parcela": (cat.crear_parcela, {"Cd14"}),
        },
        "O5.Md": {
            "modificar_parcela": (cat.modificar_parcela, {"Cd14", "Cd15"}),
            "cambiar_propietarios": (cat.cambiar_propietarios, {"Cd14", "Cd15"}),
        },
        "O5.As": {"asignar_tecnico": (cat.asignar_tecnico, {"Cd14"})},
        "O5.Ba": {"dar_de_baja_parcela": (cat.dar_de_baja_parcela, {"Cd15"})},
        "O6.Al": {"alta_cuenta": (cue.alta_cuenta, set())},
        "O6.Md": {
            "modificar_cuenta": (cue.modificar_cuenta, set()),
            "emitir_recuperacion": (cue.emitir_recuperacion, {"Cd13"}),
        },
        "O6.AR": {
            "asignar_rol": (cue.asignar_rol, {"Cd13"}),
            "revocar_rol": (cue.revocar_rol, {"Cd13"}),
        },
        "O6.Ba": {"dar_de_baja_cuenta": (cue.dar_de_baja_cuenta, {"Cd13"})},
        "O6.Sv": {"solicitar_ventana": (cue.solicitar_ventana, {"Cd23"})},
        "O6.Av": {"abrir_ventana": (cue.abrir_ventana, {"Cd23"})},
        "O6.Ae": {"autorizar_emergencia": (cue.autorizar_emergencia, {"Cd24"})},
        "O8.Rs": {"resolver_alerta": (alertas.resolver_alerta, {"Cd18"})},
    }


# Funciones públicas de los módulos de servicios que no pasan por el PEP, con su motivo.
EXCLUIDOS = {
    "usuarios.servicios.canjear_codigo": "pública: se canjea sin sesión con el código de un solo uso",
    "usuarios.servicios.acceso_emergencia_vigente": "la usa el PEP para el perfil de emergencia",
    "usuarios.servicios.consumir_emergencia": "la usa el PEP para el perfil de emergencia",
    "mediciones.alertas.registrar_aviso": "infraestructura de avisos que usan los servicios",
    "mediciones.alertas.prioridad_para": "infraestructura de avisos que usan los servicios",
}


# --------------------------------------------------------------------------- PEP


class PEP:
    def __init__(self, *, bitacora: Bitacora, pdp=None, cerrar_sesion=None):
        if bitacora is None or not isinstance(bitacora, Bitacora):
            raise ImproperlyConfigured("El PEP no arranca sin una bitácora configurada (BITACORA_CLIENTE).")
        self.bitacora = bitacora
        self.pdp = pdp if pdp is not None else pdp_configurado()
        self.cerrar_sesion = cerrar_sesion or (lambda sesion: None)

    @classmethod
    def desde_configuracion(cls, **opciones) -> PEP:
        return cls(bitacora=bitacora_configurada(), **opciones)

    # ----------------------------------------------------------------------- piezas comunes

    @staticmethod
    def _autenticada(sesion: Sesion) -> bool:
        return sesion.usuario is not None and getattr(sesion.usuario, "activo", False) and sesion.nivel_autenticacion >= NIVEL_CONTRASENA

    def _preparar_emergencia(self, sesion: Sesion) -> None:
        """El primer uso consume el acceso vigente; después se usa lo guardado hasta su vencimiento."""
        from usuarios import servicios as cuentas

        ahora = hora_de_la_base()
        if sesion.emergencia:
            if datetime.fromisoformat(sesion.emergencia["vence_en"]) > ahora:
                return
            sesion.emergencia = None
            return
        if cuentas.acceso_emergencia_vigente(sesion.usuario.pk):
            consumo = cuentas.consumir_emergencia(sesion.usuario.pk)
            sesion.emergencia = {"rol_suplido": consumo.rol_suplido, "vence_en": consumo.vence_en.isoformat()}

    @staticmethod
    def _roles_propios(sesion: Sesion) -> list[str]:
        return sorted(
            RolUsuario.objects.filter(usuario_id=sesion.usuario.pk, hasta__isnull=True).values_list("rol_id", flat=True)
        )

    @staticmethod
    def _roles_efectivos(sesion: Sesion, propios: list[str]) -> list[str]:
        return [sesion.emergencia["rol_suplido"]] if sesion.emergencia else propios

    def _entrada(self, operacion: str, sesion: Sesion, propios: list[str], hechos: pip.Hechos) -> dict:
        emergencia = {"rol_suplido": sesion.emergencia["rol_suplido"]} if sesion.emergencia else None
        return {
            "sujeto": {"id": firma.seudonimo(sesion.usuario.pk), "roles": propios, "emergencia": emergencia},
            "operacion": operacion,
            "hechos": hechos.hechos,
            "parametros": pip.parametros_politica(),
        }

    def _consultar(self, entrada: dict) -> dict | None:
        try:
            return self.pdp.decidir(entrada)
        except Exception:
            return None

    def _evento(self, tipo: str, operacion: str, sesion: Sesion, objeto: pip.Objeto, **datos) -> dict:
        return {
            "tipo": tipo,
            "operacion": operacion,
            "sujeto": firma.seudonimo(sesion.usuario.pk) if sesion.usuario is not None else None,
            "objeto": {"tipo": objeto.tipo, "id": str(objeto.id) if objeto.id is not None else None},
            **datos,
        }

    def _registrar_evento(self, evento: dict) -> bool:
        try:
            self.bitacora.registrar(evento)
            return True
        except Exception:
            return False

    def _bitacora_disponible(self) -> bool:
        try:
            return self.bitacora.disponible() is True
        except Exception:
            return False

    @staticmethod
    def _registrar_acceso(sesion: Sesion, operacion: str, hechos: pip.Hechos, resultado: str, motivo) -> None:
        with transaction.atomic():
            RegistroAcceso.objects.create(
                usuario_id=sesion.usuario.pk, parcela_id=hechos.parcela_id, operacion=operacion,
                ajena=hechos.ajena, resultado=resultado, motivo=motivo,
            )

    @staticmethod
    def _aviso_reciente(tipo: str, usuario_id) -> bool:
        desde = hora_de_la_base() - VENTANA_AVISOS
        return Alerta.objects.filter(tipo=tipo, usuario_id=usuario_id, creada_en__gt=desde).exists()

    def _aviso_umbral_blando(self, sesion: Sesion, operacion: str) -> None:
        """Una vez cada 24 horas por usuario. Si no se puede registrar, la lectura se deniega."""
        with transaction.atomic():
            if not self._aviso_reciente(TIPO_H2_UMBRAL_BLANDO, sesion.usuario.pk):
                alertas.registrar_aviso(TIPO_H2_UMBRAL_BLANDO, sesion.usuario.pk, detalle={"operacion": operacion})

    def _alerta_denegaciones_cd2(self, sesion: Sesion) -> None:
        """Tres denegaciones por Cd2 en 24 horas avisan a R7. Si el aviso falla, la denegación sigue."""
        try:
            with transaction.atomic():
                desde = hora_de_la_base() - VENTANA_AVISOS
                denegaciones = RegistroAcceso.objects.filter(
                    usuario_id=sesion.usuario.pk, resultado=RegistroAcceso.Resultado.DENEGADO, motivo="Cd2",
                    sello__gt=desde,
                ).count()
                if denegaciones >= DENEGACIONES_CD2_PARA_ALERTA and not self._aviso_reciente(
                    TIPO_DENEGACIONES_CD2, sesion.usuario.pk
                ):
                    alertas.registrar_aviso(
                        TIPO_DENEGACIONES_CD2, sesion.usuario.pk, prioridad=alertas.PRIORITARIA,
                        detalle={"denegaciones": denegaciones},
                    )
        except Exception:
            pass

    # ----------------------------------------------------------------------- lecturas y decisiones

    def decidir(self, operacion: str, sesion: Sesion, objeto: pip.Objeto | None = None) -> Concedido | Denegado:
        objeto = objeto or pip.Objeto()
        if not self._autenticada(sesion):
            return Denegado(DEFECTO, "sin sesión autenticada")
        try:
            self._preparar_emergencia(sesion)
        except Exception:
            return Denegado(DEFECTO, "no se pudo resolver el perfil de emergencia")
        with transaction.atomic(), como_actor(sesion.usuario.pk):
            resultado, cerrar = self._decidir(operacion, sesion, objeto)
        if cerrar:
            self.cerrar_sesion(sesion)
        if not resultado.permitido:
            self._registrar_evento(self._evento("denegado", operacion, sesion, objeto, condicion=resultado.condicion))
        return resultado

    def _decidir(self, operacion, sesion, objeto) -> tuple[Concedido | Denegado, bool]:
        lectura = motor.tipo_de(operacion) == "L" if "." in operacion else False
        propios = self._roles_propios(sesion)
        roles = self._roles_efectivos(sesion, propios)
        try:
            with transaction.atomic():
                hechos = pip.reunir(sesion, roles, operacion, objeto, self.bitacora)
        except Exception:
            hechos = pip.Hechos({})
            return self._denegar_lectura(sesion, operacion, hechos, lectura, DEFECTO, "falla del PIP"), False
        decision = self._consultar(self._entrada(operacion, sesion, propios, hechos))
        if decision is None:
            return self._denegar_lectura(sesion, operacion, hechos, lectura, DEFECTO, "falla del PDP"), False
        if not decision["permitir"]:
            denegado = self._denegar_lectura(sesion, operacion, hechos, lectura, decision["razon"], "política")
            if decision["razon"] == "Cd2" and lectura:
                self._alerta_denegaciones_cd2(sesion)
            return denegado, motor.RESTRICCION_CERRAR in decision["restricciones"]
        if motor.RESTRICCION_2FA in decision["restricciones"] and not sesion.segundo_factor_reciente():
            raise ReautenticacionRequerida("La operación exige un segundo factor reciente.")
        if motor.RESTRICCION_AVISO in decision["restricciones"]:
            try:
                self._aviso_umbral_blando(sesion, operacion)
            except Exception:
                return self._denegar_lectura(sesion, operacion, hechos, lectura, "Cd9", "aviso a R7 no registrado"), False
        if decision["registrar_lectura"] and not self._registrar_evento(
            self._evento("lectura", operacion, sesion, objeto, proyeccion=decision["proyeccion"])
        ):
            return self._denegar_lectura(sesion, operacion, hechos, lectura, "Cd17", "lectura no registrada"), False
        if lectura:
            try:
                self._registrar_acceso(sesion, operacion, hechos, RegistroAcceso.Resultado.CONCEDIDO, None)
            except Exception:
                return Denegado(DEFECTO, "registro del intento fallido"), False
        return Concedido(decision), False

    def _denegar_lectura(self, sesion, operacion, hechos, lectura, condicion, motivo) -> Denegado:
        if lectura:
            try:
                self._registrar_acceso(sesion, operacion, hechos, RegistroAcceso.Resultado.DENEGADO, condicion)
            except Exception:
                pass
        return Denegado(condicion, motivo)

    # ----------------------------------------------------------------------- escrituras

    def servicio_de(self, operacion: str, nombre: str | None):
        opciones = servicios().get(operacion)
        if not opciones:
            raise ValueError(f"La operación {operacion} no tiene servicio en el mapa del PEP.")
        if nombre is None:
            if len(opciones) != 1:
                raise ValueError(f"La operación {operacion} tiene varios servicios; indique cuál.")
            nombre = next(iter(opciones))
        if nombre not in opciones:
            raise ValueError(f"El servicio {nombre} no corresponde a la operación {operacion}.")
        funcion, declaradas = opciones[nombre]
        return nombre, funcion, declaradas

    def ejecutar(self, operacion: str, sesion: Sesion, objeto: pip.Objeto | None = None, *,
                 servicio: str | None = None, **argumentos) -> Concedido | Denegado:
        if motor.tipo_de(operacion) == "L":
            raise ValueError("Las lecturas pasan por decidir().")
        nombre, funcion, declaradas = self.servicio_de(operacion, servicio)
        objeto = objeto or pip.Objeto()
        resultado = self._ejecutar(operacion, sesion, objeto, nombre, funcion, declaradas, argumentos)
        tipo = "resultado" if resultado.permitido else "denegado"
        datos = {"servicio": nombre} if resultado.permitido else {"servicio": nombre, "condicion": resultado.condicion}
        if sesion.usuario is not None:
            self._registrar_evento(self._evento(tipo, operacion, sesion, objeto, **datos))
        return resultado

    def _ejecutar(self, operacion, sesion, objeto, nombre, funcion, declaradas, argumentos):
        if not self._autenticada(sesion):
            return Denegado(DEFECTO, "sin sesión autenticada")
        try:
            self._preparar_emergencia(sesion)
        except Exception:
            return Denegado(DEFECTO, "no se pudo resolver el perfil de emergencia")
        cerrar = False
        with transaction.atomic(), como_actor(sesion.usuario.pk):
            propios = self._roles_propios(sesion)
            roles = self._roles_efectivos(sesion, propios)
            try:
                with transaction.atomic():
                    hechos = pip.reunir(sesion, roles, operacion, objeto, self.bitacora)
            except Exception:
                return Denegado(DEFECTO, "falla del PIP")
            permisos = motor.matriz()["operaciones"].get(operacion) or {}
            candidatas = [c for r in roles for c in permisos.get(r, [])]
            dependiente = next((c for c in candidatas if c in motor.politica()["condiciones_bitacora"]), None)
            if dependiente and not self._bitacora_disponible():
                return Denegado(dependiente, "bitácora no disponible")
            decision = self._consultar(self._entrada(operacion, sesion, propios, hechos))
        if decision is None:
            return Denegado(DEFECTO, "falla del PDP")
        if not decision["permitir"]:
            cerrar = motor.RESTRICCION_CERRAR in decision["restricciones"]
            if cerrar:
                self.cerrar_sesion(sesion)
            return Denegado(decision["razon"], "política")
        if motor.RESTRICCION_2FA in decision["restricciones"] and not sesion.segundo_factor_reciente():
            raise ReautenticacionRequerida("La operación exige un segundo factor reciente.")
        faltantes = [c for c in decision["condiciones_servicio"] if c not in declaradas]
        if faltantes:
            return Denegado(faltantes[0], f"el servicio {nombre} no declara aplicar la condición")
        if not self._registrar_evento(self._evento("intento", operacion, sesion, objeto, servicio=nombre)):
            return Denegado(dependiente or DEFECTO, "no se pudo registrar el intento")
        try:
            resultado = funcion(sesion.usuario, **argumentos)
        except ReglaIncumplida as error:
            return Denegado(error.condicion, error.motivo)
        except NoEncontrado:
            return Denegado(DEFECTO, "objeto no encontrado")
        except ReautenticacionRequerida:
            raise
        except Exception:
            # Falla no tipificada del servicio (por ejemplo, el aviso obligatorio que no se registra):
            # se deniega con la condición de servicio que la operación exige.
            servicio_condiciones = decision["condiciones_servicio"]
            return Denegado(servicio_condiciones[0] if servicio_condiciones else DEFECTO, "falla del servicio")
        return Concedido(decision, resultado)
