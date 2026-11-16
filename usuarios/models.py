"""Usuarios, roles y reglas de separación de funciones.

Las reglas que dependen de otras filas (exclusión estática de roles) se aplican con triggers
definidos en las migraciones; aquí solo se declaran las restricciones de una fila.
"""

import uuid
from datetime import timedelta

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.db.models import F, Q
from django.utils import timezone

DURACION_MAXIMA_EMERGENCIA = timedelta(hours=4)
PERFIL_SOLO_LECTURA = "solo_lectura"


class ModeloConUUID(models.Model):
    """Base con clave primaria UUID generada en la aplicación (sin secuencias en la base)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class Rol(models.Model):
    """Rol del sistema (R1 a R7)."""

    codigo = models.CharField(max_length=2, primary_key=True)
    nombre = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.codigo} {self.nombre}"


class UsuarioManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, correo, nombre, password=None):
        """Crea un usuario; sin contraseña queda con una contraseña inutilizable."""
        if not correo:
            raise ValueError("El correo es obligatorio.")
        # Todo en minúsculas: el inicio de sesión busca el correo normalizado así.
        usuario = self.model(correo=correo.strip().lower(), nombre=nombre)
        usuario.set_password(password)
        usuario.save(using=self._db)
        return usuario


class Usuario(ModeloConUUID, AbstractBaseUser):
    """Cuenta de usuario. Sin permisos de Django ni superusuarios: la autorización es propia."""

    correo = models.EmailField(unique=True)
    nombre = models.CharField(max_length=150)
    activo = models.BooleanField(default=True)
    creado_en = models.DateTimeField(default=timezone.now)
    # Secreto TOTP cifrado con AES-256-GCM (ver usuarios.cifrado); nunca en claro.
    totp_secreto_cifrado = models.BinaryField(null=True, blank=True)
    # db_default deja el DEFAULT también en la base, para los INSERT hechos por SQL.
    totp_confirmado = models.BooleanField(default=False, db_default=False)
    totp_ultimo_paso = models.BigIntegerField(null=True)
    intentos_fallidos = models.PositiveSmallIntegerField(default=0, db_default=0)
    bloqueado_hasta = models.DateTimeField(null=True)

    objects = UsuarioManager()

    USERNAME_FIELD = "correo"
    EMAIL_FIELD = "correo"
    REQUIRED_FIELDS = ["nombre"]

    @property
    def is_active(self):
        return self.activo

    def __str__(self):
        return self.correo


class RolUsuario(ModeloConUUID):
    """Asignación de un rol a un usuario. Vigente mientras `hasta` sea NULL."""

    usuario = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="asignaciones_rol")
    rol = models.ForeignKey(Rol, on_delete=models.PROTECT, related_name="+")
    desde = models.DateTimeField(default=timezone.now)
    hasta = models.DateTimeField(null=True, blank=True)
    asignado_por = models.ForeignKey(
        Usuario, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["usuario", "rol"],
                condition=Q(hasta__isnull=True),
                name="rolusuario_vigente_unico",
            ),
        ]


class ExclusionEstatica(models.Model):
    """Par de roles que un mismo usuario no puede tener vigentes a la vez (rol_a < rol_b)."""

    rol_a = models.ForeignKey(Rol, on_delete=models.PROTECT, related_name="+")
    rol_b = models.ForeignKey(Rol, on_delete=models.PROTECT, related_name="+")

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(rol_a__lt=F("rol_b")), name="exclusion_orden_roles"),
            models.UniqueConstraint(fields=["rol_a", "rol_b"], name="exclusion_par_unico"),
        ]


class VentanaAuditoria(ModeloConUUID):
    """Período en que un auditor externo (R5) puede consultar."""

    auditor = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    inicio = models.DateTimeField()
    fin = models.DateTimeField()
    abierta_por = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    solicitada_por = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(fin__gt=F("inicio")), name="ventana_fin_posterior"),
        ]


class AccesoEmergencia(ModeloConUUID):
    """Acceso temporal de solo lectura autorizado por un R4 y un R7 distintos."""

    beneficiario = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    autorizado_por_r4 = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    autorizado_por_r7 = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    perfil = models.CharField(max_length=20, default=PERFIL_SOLO_LECTURA)
    inicio = models.DateTimeField()
    fin = models.DateTimeField()
    usado_en = models.DateTimeField(null=True, blank=True)
    revisado_en = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(perfil=PERFIL_SOLO_LECTURA), name="emergencia_solo_lectura"
            ),
            models.CheckConstraint(condition=Q(fin__gt=F("inicio")), name="emergencia_fin_posterior"),
            models.CheckConstraint(
                condition=Q(fin__lte=F("inicio") + DURACION_MAXIMA_EMERGENCIA),
                name="emergencia_duracion_maxima",
            ),
            models.CheckConstraint(
                condition=~Q(beneficiario=F("autorizado_por_r4")),
                name="emergencia_beneficiario_distinto_r4",
            ),
            models.CheckConstraint(
                condition=~Q(beneficiario=F("autorizado_por_r7")),
                name="emergencia_beneficiario_distinto_r7",
            ),
            models.CheckConstraint(
                condition=~Q(autorizado_por_r4=F("autorizado_por_r7")),
                name="emergencia_autorizadores_distintos",
            ),
        ]
