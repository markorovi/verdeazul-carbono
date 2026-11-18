"""Períodos, mediciones con versiones inmutables, aprobaciones, certificados, enmiendas y alertas.

Las reglas que dependen de otras filas (transiciones, H1, plazos, separación de funciones,
encadenamiento de huellas) y la visibilidad por fila (RLS) viven en los disparadores y políticas
de las migraciones; aquí solo se declaran las restricciones de una fila.
"""

from django.conf import settings
from django.db import models
from django.db.models import F, Q
from django.utils import timezone

from usuarios.models import ModeloConUUID

PATRON_HUELLA = r"^[0-9a-f]{64}$"
PATRON_TEXTO_MINIMO = r"^.{10,}$"
LARGO_NOTAS = 2000

ESTADOS_MEDICION = ["borrador", "presentada", "devuelta", "aprobada", "certificada", "sin_presentar"]
ESTADOS_ENMIENDA = ["solicitada", "autorizada", "rechazada"]
ESTADOS_CERTIFICADO = ["vigente", "anulado"]
PRIORIDADES_ALERTA = ["aviso", "prioritaria"]


def _usuario(**opciones):
    return models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+", **opciones
    )


def _co2e():
    return models.DecimalField(max_digits=14, decimal_places=3)


class Periodo(ModeloConUUID):
    class Estado(models.TextChoices):
        ABIERTO = "abierto", "Abierto"
        CERRADO = "cerrado", "Cerrado"

    inicio = models.DateField()
    fin = models.DateField()
    estado = models.CharField(max_length=10, choices=Estado.choices, default=Estado.ABIERTO)
    cerrado_en = models.DateTimeField(null=True, blank=True)
    cerrado_por = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(fin__gt=F("inicio")), name="periodo_fin_posterior"),
            models.CheckConstraint(
                condition=Q(estado__in=["abierto", "cerrado"]), name="periodo_estado_valido"
            ),
            models.CheckConstraint(
                condition=(Q(estado="abierto") & Q(cerrado_en__isnull=True))
                | (Q(estado="cerrado") & Q(cerrado_en__isnull=False)),
                name="periodo_cierre_coherente",
            ),
        ]


class PoliticaParametro(models.Model):
    """Parámetro de política sembrado por migración; la tabla es de solo lectura."""

    clave = models.CharField(max_length=50, primary_key=True)
    valor = models.DecimalField(max_digits=14, decimal_places=3)
    descripcion = models.CharField(max_length=200)


class Medicion(ModeloConUUID):
    """Una medición por parcela y período. El ciclo sube al anular su certificado."""

    class Estado(models.TextChoices):
        BORRADOR = "borrador", "Borrador"
        PRESENTADA = "presentada", "Presentada"
        DEVUELTA = "devuelta", "Devuelta"
        APROBADA = "aprobada", "Aprobada"
        CERTIFICADA = "certificada", "Certificada"
        SIN_PRESENTAR = "sin_presentar", "Sin presentar"

    parcela = models.ForeignKey("catalogo.Parcela", on_delete=models.PROTECT, related_name="+")
    periodo = models.ForeignKey(Periodo, on_delete=models.PROTECT, related_name="+")
    registrada_por = _usuario()
    estado = models.CharField(max_length=15, choices=Estado.choices, default=Estado.BORRADOR)
    ciclo = models.PositiveSmallIntegerField(default=1)
    devuelta_por = _usuario(null=True, blank=True)
    creada_en = models.DateTimeField(default=timezone.now)
    # Verificador (R2) a cargo; solo un R7 lo cambia, con la medición presentada y el período cerrado.
    verificador_asignado = _usuario(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["parcela", "periodo"], name="medicion_unica_por_parcela_periodo"),
            models.CheckConstraint(
                condition=Q(estado__in=ESTADOS_MEDICION), name="medicion_estado_valido"
            ),
            models.CheckConstraint(condition=Q(ciclo__gte=1), name="medicion_ciclo_positivo"),
        ]


class MedicionVersion(ModeloConUUID):
    """Versión inmutable de una medición; la base calcula la huella y la encadena con la anterior."""

    medicion = models.ForeignKey(Medicion, on_delete=models.PROTECT, related_name="versiones")
    numero = models.PositiveIntegerField()
    co2e_toneladas = _co2e()
    fecha_muestreo = models.DateField()
    notas = models.CharField(max_length=LARGO_NOTAS, null=True, blank=True)
    creada_por = _usuario()
    creada_en = models.DateTimeField(default=timezone.now)
    huella = models.CharField(max_length=64)
    huella_previa = models.CharField(max_length=64, null=True, blank=True)
    enmienda = models.ForeignKey(
        "Enmienda", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["medicion", "numero"], name="version_numero_unico"),
            models.UniqueConstraint(
                fields=["enmienda"], condition=Q(enmienda__isnull=False), name="version_enmienda_unica"
            ),
            models.CheckConstraint(condition=Q(numero__gte=1), name="version_numero_positivo"),
            models.CheckConstraint(condition=Q(co2e_toneladas__gt=0), name="version_co2e_positivo"),
            models.CheckConstraint(condition=Q(huella__regex=PATRON_HUELLA), name="version_huella_hex"),
            models.CheckConstraint(
                condition=Q(huella_previa__isnull=True) | Q(huella_previa__regex=PATRON_HUELLA),
                name="version_huella_previa_hex",
            ),
        ]


class Aprobacion(ModeloConUUID):
    """Aprobación inmutable de la última versión de una medición en un ciclo."""

    medicion = models.ForeignKey(Medicion, on_delete=models.PROTECT, related_name="aprobaciones")
    version = models.ForeignKey(MedicionVersion, on_delete=models.PROTECT, related_name="+")
    ciclo = models.PositiveSmallIntegerField()
    aprobador = _usuario()
    huella_aprobada = models.CharField(max_length=64)
    aprobada_en = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["medicion", "ciclo", "aprobador"], name="aprobacion_unica_por_ciclo"
            ),
            models.CheckConstraint(condition=Q(ciclo__gte=1), name="aprobacion_ciclo_positivo"),
            models.CheckConstraint(
                condition=Q(huella_aprobada__regex=PATRON_HUELLA), name="aprobacion_huella_hex"
            ),
        ]


class Enmienda(ModeloConUUID):
    """Solicitud de cambio de una medición con período cerrado; la autoriza un R7 independiente."""

    class Estado(models.TextChoices):
        SOLICITADA = "solicitada", "Solicitada"
        AUTORIZADA = "autorizada", "Autorizada"
        RECHAZADA = "rechazada", "Rechazada"

    medicion = models.ForeignKey(Medicion, on_delete=models.PROTECT, related_name="enmiendas")
    version_base = models.ForeignKey(
        MedicionVersion, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    solicitante = _usuario()
    motivo = models.TextField()
    co2e_nuevo = _co2e()
    fecha_nueva = models.DateField()
    notas_nuevas = models.CharField(max_length=LARGO_NOTAS, null=True, blank=True)
    estado = models.CharField(max_length=10, choices=Estado.choices, default=Estado.SOLICITADA)
    solicitada_en = models.DateTimeField(default=timezone.now)
    autorizador = _usuario(null=True, blank=True)
    resuelta_en = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(motivo__regex=PATRON_TEXTO_MINIMO), name="enmienda_motivo_minimo"),
            models.CheckConstraint(condition=Q(co2e_nuevo__gt=0), name="enmienda_co2e_positivo"),
            models.CheckConstraint(
                condition=Q(estado__in=ESTADOS_ENMIENDA), name="enmienda_estado_valido"
            ),
            models.CheckConstraint(
                condition=(
                    Q(estado="solicitada") & Q(autorizador__isnull=True) & Q(resuelta_en__isnull=True)
                )
                | (
                    Q(estado__in=["autorizada", "rechazada"])
                    & Q(autorizador__isnull=False)
                    & Q(resuelta_en__isnull=False)
                ),
                name="enmienda_resolucion_coherente",
            ),
            models.UniqueConstraint(
                fields=["medicion"], condition=Q(estado="solicitada"), name="enmienda_una_solicitada"
            ),
        ]


class Certificado(ModeloConUUID):
    """Certificado de una parcela y período. A lo sumo uno vigente (H1)."""

    class Estado(models.TextChoices):
        VIGENTE = "vigente", "Vigente"
        ANULADO = "anulado", "Anulado"

    parcela = models.ForeignKey("catalogo.Parcela", on_delete=models.PROTECT, related_name="+")
    periodo = models.ForeignKey(Periodo, on_delete=models.PROTECT, related_name="+")
    medicion = models.ForeignKey(Medicion, on_delete=models.PROTECT, related_name="certificados")
    version = models.ForeignKey(MedicionVersion, on_delete=models.PROTECT, related_name="+")
    ciclo = models.PositiveSmallIntegerField()
    estado = models.CharField(max_length=10, choices=Estado.choices, default=Estado.VIGENTE)
    emitido_en = models.DateTimeField(default=timezone.now)
    anulado_en = models.DateTimeField(null=True, blank=True)
    anulado_por = _usuario(null=True, blank=True)
    justificacion_anulacion = models.TextField(null=True, blank=True)
    # Documento firmado (mediciones.firma). La base valida el payload; la firma se verifica fuera.
    payload = models.JSONField()
    firma = models.TextField()
    clave_publica = models.TextField()
    alg = models.CharField(max_length=10)
    key_id = models.CharField(max_length=16)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(estado__in=ESTADOS_CERTIFICADO), name="certificado_estado_valido"
            ),
            models.CheckConstraint(condition=Q(alg="Ed25519"), name="certificado_alg_ed25519"),
            models.CheckConstraint(condition=Q(ciclo__gte=1), name="certificado_ciclo_positivo"),
            models.CheckConstraint(
                condition=(
                    Q(estado="vigente")
                    & Q(anulado_en__isnull=True)
                    & Q(anulado_por__isnull=True)
                    & Q(justificacion_anulacion__isnull=True)
                )
                | (
                    Q(estado="anulado")
                    & Q(anulado_en__isnull=False)
                    & Q(anulado_por__isnull=False)
                    & Q(justificacion_anulacion__isnull=False)
                ),
                name="certificado_anulacion_coherente",
            ),
            models.CheckConstraint(
                condition=Q(justificacion_anulacion__isnull=True)
                | Q(justificacion_anulacion__regex=PATRON_TEXTO_MINIMO),
                name="certificado_justificacion_minima",
            ),
            models.UniqueConstraint(
                fields=["parcela", "periodo"], condition=Q(estado="vigente"), name="certificado_vigente_unico"
            ),
        ]


class Alerta(ModeloConUUID):
    """Aviso o alerta. `usuario` es quien originó el evento; `cuenta_afectada`, la cuenta sobre la
    que recae (técnico asignado, propietario). Ninguno de los dos puede resolverla (Cd18).
    """

    class Prioridad(models.TextChoices):
        AVISO = "aviso", "Aviso"
        PRIORITARIA = "prioritaria", "Prioritaria"

    tipo = models.CharField(max_length=100)
    prioridad = models.CharField(max_length=12, choices=Prioridad.choices)
    usuario = _usuario(null=True, blank=True)
    cuenta_afectada = _usuario(null=True, blank=True)
    parcela = models.ForeignKey(
        "catalogo.Parcela", null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    medicion = models.ForeignKey(Medicion, null=True, blank=True, on_delete=models.PROTECT, related_name="+")
    detalle = models.JSONField(default=dict)
    creada_en = models.DateTimeField(default=timezone.now)
    resuelta_en = models.DateTimeField(null=True, blank=True)
    resuelta_por = _usuario(null=True, blank=True)
    justificacion_resolucion = models.TextField(null=True, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=Q(prioridad__in=PRIORIDADES_ALERTA), name="alerta_prioridad_valida"
            ),
            models.CheckConstraint(
                condition=(Q(resuelta_en__isnull=True) & Q(resuelta_por__isnull=True))
                | (Q(resuelta_en__isnull=False) & Q(resuelta_por__isnull=False)),
                name="alerta_resolucion_coherente",
            ),
            # Con usuario o cuenta afectada nulos la comparación es nula y la restricción se cumple.
            models.CheckConstraint(
                condition=Q(resuelta_por__isnull=True)
                | (~Q(resuelta_por=F("usuario")) & ~Q(resuelta_por=F("cuenta_afectada"))),
                name="alerta_resolucion_independiente",
            ),
        ]
