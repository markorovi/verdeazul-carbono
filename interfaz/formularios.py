"""Formularios explícitos de las operaciones: cada campo tipado y acotado, sin ModelForm.

Los formularios solo validan los argumentos del servicio. Ningún campo es atributo de la decisión:
el objeto de la operación sale de la URL y el actor, de la sesión.
"""

from __future__ import annotations

import re
import uuid
from decimal import Decimal

from django import forms
from django.core.exceptions import ValidationError

from mediciones.models import LARGO_NOTAS

ROLES = [(f"R{n}", f"R{n}") for n in range(1, 8)]
ROLES_SUPLIBLES = [("R1", "R1"), ("R2", "R2")]
MAX_UUIDS = 20
_HUELLA = re.compile(r"^[0-9a-f]{64}$")
_SEPARADOR = re.compile(r"[\s,]+")


def _co2e(etiqueta: str = "CO2e (toneladas)") -> forms.DecimalField:
    return forms.DecimalField(label=etiqueta, max_digits=14, decimal_places=3, min_value=Decimal("0.001"))


def _fecha(etiqueta: str) -> forms.DateField:
    return forms.DateField(label=etiqueta, input_formats=["%Y-%m-%d"],
                           widget=forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"))


def _fecha_hora(etiqueta: str) -> forms.DateTimeField:
    return forms.DateTimeField(label=f"{etiqueta} (UTC)", input_formats=["%Y-%m-%dT%H:%M"],
                               widget=forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"))


def _notas(etiqueta: str = "Notas") -> forms.CharField:
    return forms.CharField(label=etiqueta, required=False, max_length=LARGO_NOTAS, widget=forms.Textarea(attrs={"rows": 3}))


def _justificacion(etiqueta: str = "Justificación") -> forms.CharField:
    return forms.CharField(label=etiqueta, min_length=10, max_length=LARGO_NOTAS, widget=forms.Textarea(attrs={"rows": 3}))


class ListaDeUUID(forms.CharField):
    """Identificadores separados por comas o espacios; a lo sumo MAX_UUIDS, sin repetir."""

    def __init__(self, *, requerido: bool = True, **opciones):
        super().__init__(required=requerido, max_length=40 * MAX_UUIDS, **opciones)

    def to_python(self, valor):
        texto = super().to_python(valor)
        partes = [p for p in _SEPARADOR.split(texto or "") if p]
        if len(partes) > MAX_UUIDS:
            raise ValidationError(f"Indique a lo sumo {MAX_UUIDS} identificadores.")
        try:
            identificadores = [uuid.UUID(p) for p in partes]
        except ValueError:
            raise ValidationError("Hay un identificador que no es un UUID válido.") from None
        return list(dict.fromkeys(identificadores))

    def validate(self, valor):
        if self.required and not valor:
            raise ValidationError("Indique al menos un identificador.")


class Confirmacion(forms.Form):
    """Operaciones sin argumentos propios: solo se confirma."""


class RegistrarMedicion(forms.Form):
    periodo_id = forms.UUIDField(label="Período")
    co2e_toneladas = _co2e()
    fecha_muestreo = _fecha("Fecha de muestreo")
    notas = _notas()


class ModificarMedicion(forms.Form):
    co2e_toneladas = _co2e()
    fecha_muestreo = _fecha("Fecha de muestreo")
    notas = _notas()


class Revision(forms.Form):
    """La huella de la versión que el verificador revisó; la base la compara con la vigente (Cd7)."""

    huella_revisada = forms.CharField(min_length=64, max_length=64, widget=forms.HiddenInput)

    def clean_huella_revisada(self):
        valor = self.cleaned_data["huella_revisada"]
        if not _HUELLA.match(valor):
            raise ValidationError("Huella inválida.")
        return valor


class Reasignar(forms.Form):
    destino_id = forms.UUIDField(label="Verificador de destino")


class AbrirPeriodo(forms.Form):
    inicio = _fecha("Inicio")
    fin = _fecha("Fin")


class Justificacion(forms.Form):
    justificacion = _justificacion()


class SolicitarEnmienda(forms.Form):
    motivo = _justificacion("Motivo")
    co2e_nuevo = _co2e("CO2e nuevo (toneladas)")
    fecha_nueva = _fecha("Fecha de muestreo nueva")
    notas_nuevas = _notas("Notas nuevas")


class ResolverEnmienda(forms.Form):
    decision = forms.ChoiceField(label="Decisión", choices=[("autorizar", "Autorizar"), ("rechazar", "Rechazar")])


class CrearFinca(forms.Form):
    nombre = forms.CharField(label="Nombre", max_length=200)
    propietarios = ListaDeUUID(label="Propietarios (identificadores)")


class CrearParcela(forms.Form):
    codigo = forms.CharField(label="Código", max_length=50)
    wkt = forms.CharField(label="Geometría (WKT, CRTM05)", max_length=20000, widget=forms.Textarea(attrs={"rows": 3}))


class ModificarParcela(forms.Form):
    codigo = forms.CharField(label="Código nuevo", max_length=50, required=False)
    wkt = forms.CharField(label="Geometría nueva (WKT)", max_length=20000, required=False,
                          widget=forms.Textarea(attrs={"rows": 3}))

    def clean(self):
        datos = super().clean()
        if not datos.get("codigo") and not datos.get("wkt"):
            raise ValidationError("Indique el código, la geometría o ambos.")
        return datos


class CambiarPropietarios(forms.Form):
    agregar = ListaDeUUID(label="Agregar (identificadores)", requerido=False)
    retirar = ListaDeUUID(label="Retirar (identificadores)", requerido=False)

    def clean(self):
        datos = super().clean()
        if not datos.get("agregar") and not datos.get("retirar"):
            raise ValidationError("Indique a quién agregar o retirar.")
        return datos


class AsignarTecnico(forms.Form):
    tecnico_id = forms.UUIDField(label="Técnico")
    vence_en = _fecha_hora("Vence")


class AltaCuenta(forms.Form):
    correo = forms.EmailField(label="Correo", max_length=254)
    nombre = forms.CharField(label="Nombre", max_length=150)


class ModificarCuenta(forms.Form):
    nombre = forms.CharField(label="Nombre", max_length=150)


class Rol(forms.Form):
    rol = forms.ChoiceField(label="Rol", choices=ROLES)


class SolicitarVentana(forms.Form):
    inicio = _fecha_hora("Inicio")
    fin = _fecha_hora("Fin")


class AutorizarEmergencia(forms.Form):
    rol_suplido = forms.ChoiceField(label="Rol suplido", choices=ROLES_SUPLIBLES)


class IrAOperacion(forms.Form):
    """Desde la consola: operación y objeto para construir la ruta (GET, sin efectos)."""

    clave = forms.CharField(max_length=40)
    objeto = forms.UUIDField()


class Pagina(forms.Form):
    pagina = forms.IntegerField(min_value=1, max_value=10000, required=False)
    tamano = forms.IntegerField(min_value=1, max_value=20, required=False)


class FiltroBitacora(forms.Form):
    antes_de = forms.IntegerField(min_value=2, required=False)
