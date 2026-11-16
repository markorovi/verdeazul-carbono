from django import forms

from usuarios.totp import DIGITOS


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
    codigo = forms.CharField(
        label="Código de verificación",
        min_length=DIGITOS,
        max_length=DIGITOS,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "inputmode": "numeric",
                "pattern": f"[0-9]{{{DIGITOS}}}",
                "autofocus": True,
            }
        ),
    )
