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
    # Quién dio de alta la cuenta. Se escribe solo al insertar (app_rw no tiene UPDATE sobre ella);
    # define la prioridad de los avisos cuando esa misma persona opera sobre la cuenta.
    creado_por = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

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
    """Período en que un auditor externo (R5) puede consultar.

    Nace como solicitud (abierta_por nulo) y solo da acceso cuando otra persona la abre; la función
    de RLS app_ventana_auditoria_vigente ignora las solicitudes sin abrir.
    """

    auditor = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    inicio = models.DateTimeField()
    fin = models.DateTimeField()
    abierta_por = models.ForeignKey(Usuario, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    solicitada_por = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    solicitada_en = models.DateTimeField(null=True, blank=True)
    abierta_en = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(fin__gt=F("inicio")), name="ventana_fin_posterior"),
            models.CheckConstraint(
                condition=Q(abierta_en__isnull=True) | Q(abierta_por__isnull=False),
                name="ventana_apertura_con_autor",
            ),
            models.CheckConstraint(
                condition=~Q(abierta_por=F("solicitada_por")), name="ventana_apertura_independiente"
            ),
        ]


ROLES_SUPLIBLES = ["R1", "R2"]


class AccesoEmergencia(ModeloConUUID):
    """Acceso temporal de solo lectura autorizado por un R4 y un R7 distintos.

    La primera autorización crea el registro pendiente (sin inicio ni fin); la segunda lo activa.
    """

    beneficiario = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    autorizado_por_r4 = models.ForeignKey(Usuario, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    autorizado_por_r7 = models.ForeignKey(Usuario, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    rol_suplido = models.ForeignKey(Rol, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    perfil = models.CharField(max_length=20, default=PERFIL_SOLO_LECTURA)
    inicio = models.DateTimeField(null=True, blank=True)
    fin = models.DateTimeField(null=True, blank=True)
    usado_en = models.DateTimeField(null=True, blank=True)
    revisado_en = models.DateTimeField(null=True, blank=True)
    revision_vence_en = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(inicio__isnull=True, fin__isnull=True) | Q(inicio__isnull=False, fin__isnull=False),
                name="emergencia_vigencia_coherente",
            ),
            models.CheckConstraint(
                condition=Q(inicio__isnull=True)
                | Q(autorizado_por_r4__isnull=False, autorizado_por_r7__isnull=False),
                name="emergencia_activa_con_dos_autorizadores",
            ),
            models.CheckConstraint(
                condition=Q(autorizado_por_r4__isnull=False) | Q(autorizado_por_r7__isnull=False),
                name="emergencia_con_autorizador",
            ),
            models.CheckConstraint(
                condition=Q(inicio__isnull=False) | Q(usado_en__isnull=True, revisado_en__isnull=True),
                name="emergencia_pendiente_sin_uso",
            ),
            models.CheckConstraint(
                condition=Q(rol_suplido__isnull=True) | Q(rol_suplido__in=ROLES_SUPLIBLES),
                name="emergencia_rol_suplido",
            ),
            models.UniqueConstraint(
                fields=["beneficiario"], condition=Q(inicio__isnull=True), name="emergencia_una_pendiente"
            ),
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

MAX_INTENTOS_CODIGO = 5


class CodigoUnUso(ModeloConUUID):
    """Código de un solo uso para el alta o la recuperación de una cuenta.

    Solo se guarda la huella SHA-256 del código; el código en claro se entrega una vez y no se
    persiste. Al llegar a MAX_INTENTOS_CODIGO intentos fallidos queda invalidado.
    """

    class Proposito(models.TextChoices):
        ALTA = "alta", "Alta"
        RECUPERACION = "recuperacion", "Recuperación"

    usuario = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    proposito = models.CharField(max_length=15, choices=Proposito.choices)
    huella = models.CharField(max_length=64)
    emitido_por = models.ForeignKey(Usuario, on_delete=models.PROTECT, related_name="+")
    emitido_en = models.DateTimeField()
    vence_en = models.DateTimeField()
    usado_en = models.DateTimeField(null=True, blank=True)
    intentos_fallidos = models.PositiveSmallIntegerField(default=0, db_default=0)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(proposito__in=["alta", "recuperacion"]), name="codigo_proposito_valido"
            ),
            models.CheckConstraint(condition=Q(huella__regex=r"^[0-9a-f]{64}$"), name="codigo_huella_hex"),
            models.CheckConstraint(condition=Q(vence_en__gt=F("emitido_en")), name="codigo_vence_despues"),
            models.CheckConstraint(
                condition=Q(intentos_fallidos__lte=MAX_INTENTOS_CODIGO), name="codigo_intentos_maximos"
            ),
            models.UniqueConstraint(fields=["huella"], name="codigo_huella_unica"),
        ]
