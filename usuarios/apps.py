from django.apps import AppConfig


class UsuariosConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "usuarios"
    verbose_name = "Usuarios y roles"

    def ready(self):
        from usuarios.autenticacion import _hash_ficticio

        # Calculado al arrancar: así la primera verificación de una cuenta inexistente no tarda
        # distinto de las demás.
        _hash_ficticio()
