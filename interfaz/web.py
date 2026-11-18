"""Puerta de las vistas: sesión, PEP y traducción de sus resultados a respuestas HTTP.

Toda vista lleva uno de tres marcadores, que la prueba estructural comprueba en cada ruta:

- @operacion("O1.Ap", objeto="medicion"): exige sesión con segundo factor y entrega a la vista un
  `Operacion` que pide al PEP la decisión (decidir) o la ejecución (ejecutar). El contexto sale de la
  sesión y del identificador de la URL; nada del cuerpo es atributo de la decisión. El cuerpo solo
  aporta los argumentos del servicio, ya validados por un formulario explícito.
- @autenticada: páginas con sesión que no leen objetos protegidos (la consola, la cuenta propia, la
  salida, la reautenticación).
- @publica: las pocas rutas sin sesión (acceso, segundo factor, recuperación, salud, verificación
  pública, clave pública y estáticos).

Traducción:
- Concedido: la vista responde.
- Denegado: 403 con la regla y un motivo breve de un catálogo fijo (nunca el motivo interno).
- Denegado por una dependencia caída (bitácora, PDP, PIP o registro): 503 genérico.
- ReautenticacionRequerida: los datos ya validados del formulario quedan pendientes en la sesión y
  se pide el segundo factor; después se vuelve a mostrar el formulario para confirmarlo. El POST
  nunca se reenvía solo.
"""

from __future__ import annotations

import time
from functools import wraps
from urllib.parse import urlencode

from django.contrib.auth import logout
from django.shortcuts import redirect, render
from django.urls import reverse

from autorizacion import pep as pep_modulo
from autorizacion.pip import Objeto
from usuarios import autenticacion

MARCA = "verdeazul_acceso"
PUBLICA = "publica"
SESION = "sesion"
OPERACION = "operacion"
CLAVE_PENDIENTE = "operacion_pendiente"
PENDIENTE_SEGUNDOS = 300
# Condiciones cuya denegación se debe a la bitácora caída (Cd17: la lectura no se puede registrar).
CONDICIONES_DE_INFRAESTRUCTURA = {"Cd17"}

MOTIVOS_BREVES = {
    "defecto": "La operación no está permitida para sus roles o el objeto no está disponible.",
    "Cd1": "No tiene una asignación vigente sobre la parcela.",
    "Cd2": "No es propietario del objeto en la fecha que corresponde.",
    "Cd3": "No tiene una ventana de auditoría vigente.",
    "Cd4": "La operación exige el segundo factor.",
    "Cd5": "El período no está abierto o no admite la operación.",
    "Cd6": "La medición ya no está en borrador o no es suya.",
    "Cd7": "La medición cambió o no está en revisión; vuelva a revisarla.",
    "Cd8": "Separación de funciones: no puede revisar esta medición.",
    "Cd9": "Se superó el límite de consultas de parcelas ajenas.",
    "Cd10": "La medición ya tiene un certificado vigente o no admite aprobación.",
    "Cd11": "La enmienda no cumple las condiciones de solicitud.",
    "Cd12": "La enmienda no cumple las condiciones de autorización.",
    "Cd13": "La operación sobre la cuenta o el rol no está permitida.",
    "Cd14": "Los datos del catálogo no cumplen las reglas.",
    "Cd15": "La parcela tiene mediciones en curso o certificadas.",
    "Cd16": "No hay una proyección disponible para su rol.",
    "Cd17": "La lectura no se pudo registrar en la bitácora.",
    "Cd18": "La alerta no se puede resolver por quien la originó o la recibe.",
    "Cd19": "La reasignación no cumple las condiciones.",
    "Cd20": "La anulación no cumple las condiciones.",
    "Cd21": "La medición no está disponible para verificación.",
    "Cd22": "La parcela no pertenece a su región.",
    "Cd23": "La ventana de auditoría no cumple las condiciones.",
    "Cd24": "El acceso de emergencia no permite esta operación.",
}
MOTIVO_DE_REGLA_DE_SERVICIO = "La operación no cumple una regla del sistema."


class Rechazo(Exception):
    """El PEP denegó; lleva la denegación para traducirla a la respuesta."""

    def __init__(self, denegado: pep_modulo.Denegado):
        super().__init__(denegado.condicion)
        self.denegado = denegado


def construir_pep(request) -> pep_modulo.PEP:
    """Un PEP por petición: la bitácora y el PDP salen de la configuración; si la política pide
    cerrar la sesión (Cd9 en umbral duro), se cierra la de esta petición."""
    return pep_modulo.PEP.desde_configuracion(cerrar_sesion=lambda sesion: logout(request))


def sesion_valida(request) -> bool:
    usuario = getattr(request, "user", None)
    return bool(
        usuario is not None and usuario.is_authenticated and usuario.is_active
        and isinstance(request.session.get(autenticacion.CLAVE_MFA), (int, float))
    )


def a_acceso(request):
    destino = request.get_full_path() if request.method == "GET" else request.path
    return redirect(f"{reverse('acceso')}?{urlencode({'next': destino})}")


def es_de_infraestructura(denegado: pep_modulo.Denegado) -> bool:
    return denegado.motivo in pep_modulo.MOTIVOS_DE_INFRAESTRUCTURA or denegado.condicion in CONDICIONES_DE_INFRAESTRUCTURA


def respuesta_denegada(request, denegado: pep_modulo.Denegado):
    if es_de_infraestructura(denegado):
        return render(request, "interfaz/no_disponible.html", status=503)
    motivo = MOTIVOS_BREVES.get(denegado.condicion, MOTIVO_DE_REGLA_DE_SERVICIO)
    return render(request, "interfaz/denegado.html", {"regla": denegado.condicion, "motivo": motivo}, status=403)


def pedir_reautenticacion(request, datos: dict | None = None):
    """Guarda los datos validados (solo textos) y lleva a la pantalla de segundo factor."""
    if datos is not None:
        request.session[CLAVE_PENDIENTE] = {
            "ruta": request.path,
            "datos": {clave: str(valor) for clave, valor in datos.items()},
            "expira": time.time() + PENDIENTE_SEGUNDOS,
        }
    return redirect(f"{reverse('reautenticar')}?{urlencode({'next': request.path})}")


def datos_pendientes(request) -> dict | None:
    """Datos de una operación pendiente de confirmar en esta ruta; se consumen al leerlos."""
    pendiente = request.session.get(CLAVE_PENDIENTE)
    if not isinstance(pendiente, dict):
        return None
    if pendiente.get("ruta") != request.path or not isinstance(pendiente.get("expira"), (int, float)):
        return None
    request.session.pop(CLAVE_PENDIENTE, None)
    if pendiente["expira"] < time.time() or not isinstance(pendiente.get("datos"), dict):
        return None
    return {clave: valor for clave, valor in pendiente["datos"].items() if isinstance(valor, str)}


class Operacion:
    """Lo que la vista puede pedir al PEP para la operación de su ruta."""

    def __init__(self, request, codigo: str, objeto: Objeto):
        self.request = request
        self.codigo = codigo
        self.objeto = objeto
        self.sesion = pep_modulo.sesion_desde_request(request)
        self.pep = construir_pep(request)

    def _guardar(self) -> None:
        if self.sesion.usuario is not None and sesion_valida(self.request):
            pep_modulo.guardar_emergencia(self.request, self.sesion)

    def decidir(self, objeto: Objeto | None = None, codigo: str | None = None) -> pep_modulo.Concedido:
        try:
            resultado = self.pep.decidir(codigo or self.codigo, self.sesion, objeto or self.objeto)
        finally:
            self._guardar()
        if not resultado.permitido:
            raise Rechazo(resultado)
        return resultado

    def intentar(self, objeto: Objeto, codigo: str | None = None) -> pep_modulo.Concedido | None:
        """Para listas: una fila denegada por la política se omite; una dependencia caída corta."""
        try:
            return self.decidir(objeto, codigo)
        except Rechazo as rechazo:
            if es_de_infraestructura(rechazo.denegado):
                raise
            return None

    def ejecutar(self, servicio: str | None = None, **argumentos) -> pep_modulo.Concedido:
        try:
            resultado = self.pep.ejecutar(self.codigo, self.sesion, self.objeto, servicio=servicio, **argumentos)
        finally:
            self._guardar()
        if not resultado.permitido:
            raise Rechazo(resultado)
        return resultado


def _marcar(vista, tipo: str, codigo: str | None = None):
    setattr(vista, MARCA, (tipo, codigo))
    return vista


def publica(vista):
    return _marcar(vista, PUBLICA)


def autenticada(vista):
    @wraps(vista)
    def envuelta(request, *args, **kwargs):
        if not sesion_valida(request):
            return a_acceso(request)
        return vista(request, *args, **kwargs)

    return _marcar(envuelta, SESION)


def operacion(codigo: str, objeto: str = "ninguno"):
    """Decorador obligatorio de toda vista que lee o modifica objetos protegidos.

    El identificador del objeto sale solo del parámetro `objeto_id` de la URL.
    """

    def decorador(vista):
        @wraps(vista)
        def envuelta(request, *args, **kwargs):
            if not sesion_valida(request):
                return a_acceso(request)
            request.operacion = Operacion(request, codigo, Objeto(objeto, kwargs.get("objeto_id")))
            try:
                return vista(request, *args, **kwargs)
            except Rechazo as rechazo:
                return respuesta_denegada(request, rechazo.denegado)
            except pep_modulo.ReautenticacionRequerida:
                datos = getattr(request, "datos_validados", None)
                return pedir_reautenticacion(request, datos if request.method == "POST" else None)

        return _marcar(envuelta, OPERACION, codigo)

    return decorador
