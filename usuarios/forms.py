from django import forms

from usuarios.totp import DIGITOS


def _campo_codigo_totp(requerido: bool = True) -> forms.CharField:
    return forms.CharField(
        label="Código de verificación",
        required=requerido,
        min_length=DIGITOS,
        max_length=DIGITOS,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "pattern": f"[0-9]{{{DIGITOS}}}",
            }
        ),
    )


class AccesoForm(forms.Form):
    correo = forms.CharField(
        label="Correo",
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "username", "autofocus": True}),
    )
    password = forms.CharField(
        label="Contraseña",
        max_length=1024,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class SegundoFactorForm(forms.Form):
    codigo = _campo_codigo_totp()


class RecuperacionForm(forms.Form):
    """Canje de un código de alta o de recuperación. La recuperación exige además el código TOTP."""

    correo = forms.CharField(label="Correo", max_length=254, widget=forms.EmailInput(attrs={"autocomplete": "username"}))
    codigo = forms.CharField(label="Código de un solo uso", max_length=128, strip=True,
                             widget=forms.TextInput(attrs={"autocomplete": "off"}))
    contrasena = forms.CharField(label="Contraseña nueva", max_length=1024, strip=False,
                                 widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    confirmacion = forms.CharField(label="Repita la contraseña nueva", max_length=1024, strip=False,
                                   widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))
    codigo_totp = _campo_codigo_totp(requerido=False)

    def clean(self):
        datos = super().clean()
        if datos.get("contrasena") != datos.get("confirmacion"):
            raise forms.ValidationError("Las contraseñas no coinciden.")
        return datos
