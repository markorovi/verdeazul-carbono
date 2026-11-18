"""Solicitud y apertura de ventanas de auditoría, doble autorización de emergencias y códigos de un
solo uso (Cd23, Cd24 y recuperación de contraseña).

Solo PostgreSQL. Ninguna función es SECURITY DEFINER y todas fijan search_path.

- Ventana: abierta_por pasa a nullable (una ventana sin abrir es una solicitud) y se agregan las
  fechas de solicitud y apertura. app_rw recibe UPDATE solo sobre abierta_por_id y abierta_en; un
  disparador permite abrir una sola vez y fija abierta_en = now(). app_ventana_auditoria_vigente
  pasa a ignorar las solicitudes sin abrir: sin ese cambio, solicitar daría acceso al auditor.
- Emergencia: los autorizadores, inicio y fin pasan a nullables para el registro pendiente de la
  primera autorización; se agregan el rol suplido y el límite de revisión. app_rw recibe UPDATE
  solo sobre las columnas de la activación; un disparador impide cambiar un acceso ya activado,
  reemplazar un autorizador y usar o revisar dos veces. Las restricciones existentes (duración
  máxima, beneficiario y autorizadores distintos, solo lectura) siguen igual.
- Códigos: tabla nueva; app_rw tiene SELECT e INSERT, y UPDATE solo sobre usado_en e
  intentos_fallidos. Un disparador impide usar un código dos veces y bajar sus intentos.
"""

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models

ERROR = "integrity_constraint_violation"


def _error(mensaje: str) -> str:
    return f"RAISE EXCEPTION USING ERRCODE = '{ERROR}', MESSAGE = '{mensaje}';"


def _funcion(nombre: str, cuerpo: str) -> str:
    return f"""
CREATE FUNCTION {nombre}() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
{cuerpo}
    RETURN NEW;
END;
$$
"""


FUNCION_VENTANA = _funcion("usuarios_ventana_apertura", f"""
    IF OLD.abierta_por_id IS NOT NULL THEN
        {_error("Ventana: ya fue abierta; una solicitud se abre una sola vez.")}
    END IF;
    IF NEW.abierta_por_id IS NULL THEN
        {_error("Ventana: abrirla exige indicar quién la abre.")}
    END IF;
    NEW.abierta_en := now();""")

FUNCION_EMERGENCIA = _funcion("usuarios_emergencia_cambio", f"""
    IF NEW.beneficiario_id <> OLD.beneficiario_id OR NEW.perfil <> OLD.perfil
       OR NEW.rol_suplido_id IS DISTINCT FROM OLD.rol_suplido_id THEN
        {_error("Emergencia: el beneficiario, el perfil y el rol suplido no cambian.")}
    END IF;
    IF (OLD.autorizado_por_r4_id IS NOT NULL AND NEW.autorizado_por_r4_id IS DISTINCT FROM OLD.autorizado_por_r4_id)
       OR (OLD.autorizado_por_r7_id IS NOT NULL AND NEW.autorizado_por_r7_id IS DISTINCT FROM OLD.autorizado_por_r7_id) THEN
        {_error("Emergencia: un autorizador registrado no se reemplaza.")}
    END IF;
    IF OLD.inicio IS NOT NULL AND (NEW.inicio IS DISTINCT FROM OLD.inicio OR NEW.fin IS DISTINCT FROM OLD.fin
       OR NEW.revision_vence_en IS DISTINCT FROM OLD.revision_vence_en) THEN
        {_error("Emergencia: un acceso activado no cambia su vigencia.")}
    END IF;
    IF OLD.usado_en IS NOT NULL AND NEW.usado_en IS DISTINCT FROM OLD.usado_en THEN
        {_error("Emergencia (Cd24): el acceso es de un solo uso.")}
    END IF;
    IF OLD.revisado_en IS NOT NULL AND NEW.revisado_en IS DISTINCT FROM OLD.revisado_en THEN
        {_error("Emergencia: la revisión ya fue registrada.")}
    END IF;""")

FUNCION_CODIGO = _funcion("usuarios_codigo_un_uso", f"""
    IF OLD.usado_en IS NOT NULL AND NEW.usado_en IS DISTINCT FROM OLD.usado_en THEN
        {_error("Código: ya fue usado.")}
    END IF;
    IF NEW.intentos_fallidos < OLD.intentos_fallidos THEN
        {_error("Código: los intentos fallidos no disminuyen.")}
    END IF;""")

FUNCION_VENTANA_VIGENTE = """
CREATE OR REPLACE FUNCTION app_ventana_auditoria_vigente() RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
    SELECT EXISTS (SELECT 1 FROM usuarios_ventanaauditoria
                    WHERE auditor_id = app_usuario_actual() AND abierta_por_id IS NOT NULL
                      AND inicio <= now() AND now() < fin)
$$
"""

FUNCION_VENTANA_VIGENTE_ORIGINAL = """
CREATE OR REPLACE FUNCTION app_ventana_auditoria_vigente() RETURNS boolean
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
    SELECT EXISTS (SELECT 1 FROM usuarios_ventanaauditoria
                    WHERE auditor_id = app_usuario_actual() AND inicio <= now() AND now() < fin)
$$
"""

DISPARADORES = [
    FUNCION_VENTANA,
    "CREATE TRIGGER usuarios_ventana_apertura BEFORE UPDATE ON usuarios_ventanaauditoria"
    " FOR EACH ROW EXECUTE FUNCTION usuarios_ventana_apertura()",
    FUNCION_EMERGENCIA,
    "CREATE TRIGGER usuarios_emergencia_cambio BEFORE UPDATE ON usuarios_accesoemergencia"
    " FOR EACH ROW EXECUTE FUNCTION usuarios_emergencia_cambio()",
    FUNCION_CODIGO,
    "CREATE TRIGGER usuarios_codigo_un_uso BEFORE UPDATE ON usuarios_codigounuso"
    " FOR EACH ROW EXECUTE FUNCTION usuarios_codigo_un_uso()",
]
QUITAR_DISPARADORES = [
    "DROP TRIGGER usuarios_codigo_un_uso ON usuarios_codigounuso",
    "DROP FUNCTION usuarios_codigo_un_uso()",
    "DROP TRIGGER usuarios_emergencia_cambio ON usuarios_accesoemergencia",
    "DROP FUNCTION usuarios_emergencia_cambio()",
    "DROP TRIGGER usuarios_ventana_apertura ON usuarios_ventanaauditoria",
    "DROP FUNCTION usuarios_ventana_apertura()",
]


def _bloque_app_rw(sentencias: list[str]) -> str:
    """Solo corre si existe app_rw (sin él, nadie escribe: falla cerrado)."""
    cuerpo = "\n".join(f"        {s};" for s in sentencias)
    return f"""
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
{cuerpo}
    END IF;
END
$$
"""


PERMISOS = _bloque_app_rw([
    "GRANT UPDATE (abierta_por_id, abierta_en) ON usuarios_ventanaauditoria TO app_rw",
    "GRANT UPDATE (autorizado_por_r4_id, autorizado_por_r7_id, inicio, fin, revision_vence_en)"
    " ON usuarios_accesoemergencia TO app_rw",
    "GRANT SELECT, INSERT ON usuarios_codigounuso TO app_rw",
    "GRANT UPDATE (usado_en, intentos_fallidos) ON usuarios_codigounuso TO app_rw",
])
QUITAR_PERMISOS = _bloque_app_rw([
    "REVOKE UPDATE (abierta_por_id, abierta_en) ON usuarios_ventanaauditoria FROM app_rw",
    "REVOKE UPDATE (autorizado_por_r4_id, autorizado_por_r7_id, inicio, fin, revision_vence_en)"
    " ON usuarios_accesoemergencia FROM app_rw",
    "REVOKE ALL ON usuarios_codigounuso FROM app_rw",
])


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0004_usuario_creado_por'),
        ('mediciones', '0004_reglas_inmutabilidad_rls'),
    ]
    operations = [
        migrations.CreateModel(
            name='CodigoUnUso',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('proposito', models.CharField(choices=[('alta', 'Alta'), ('recuperacion', 'Recuperación')], max_length=15)),
                ('huella', models.CharField(max_length=64)),
                ('emitido_en', models.DateTimeField()),
                ('vence_en', models.DateTimeField()),
                ('usado_en', models.DateTimeField(blank=True, null=True)),
                ('intentos_fallidos', models.PositiveSmallIntegerField(db_default=0, default=0)),
            ],
        ),
        migrations.AddField(
            model_name='accesoemergencia',
            name='revision_vence_en',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='accesoemergencia',
            name='rol_suplido',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='usuarios.rol'),
        ),
        migrations.AddField(
            model_name='ventanaauditoria',
            name='abierta_en',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='ventanaauditoria',
            name='solicitada_en',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='accesoemergencia',
            name='autorizado_por_r4',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='accesoemergencia',
            name='autorizado_por_r7',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='accesoemergencia',
            name='fin',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='accesoemergencia',
            name='inicio',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='ventanaauditoria',
            name='abierta_por',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddConstraint(
            model_name='accesoemergencia',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('fin__isnull', True), ('inicio__isnull', True)), models.Q(('fin__isnull', False), ('inicio__isnull', False)), _connector='OR'), name='emergencia_vigencia_coherente'),
        ),
        migrations.AddConstraint(
            model_name='accesoemergencia',
            constraint=models.CheckConstraint(condition=models.Q(('inicio__isnull', True), models.Q(('autorizado_por_r4__isnull', False), ('autorizado_por_r7__isnull', False)), _connector='OR'), name='emergencia_activa_con_dos_autorizadores'),
        ),
        migrations.AddConstraint(
            model_name='accesoemergencia',
            constraint=models.CheckConstraint(condition=models.Q(('autorizado_por_r4__isnull', False), ('autorizado_por_r7__isnull', False), _connector='OR'), name='emergencia_con_autorizador'),
        ),
        migrations.AddConstraint(
            model_name='accesoemergencia',
            constraint=models.CheckConstraint(condition=models.Q(('inicio__isnull', False), models.Q(('revisado_en__isnull', True), ('usado_en__isnull', True)), _connector='OR'), name='emergencia_pendiente_sin_uso'),
        ),
        migrations.AddConstraint(
            model_name='accesoemergencia',
            constraint=models.CheckConstraint(condition=models.Q(('rol_suplido__isnull', True), ('rol_suplido__in', ['R1', 'R2']), _connector='OR'), name='emergencia_rol_suplido'),
        ),
        migrations.AddConstraint(
            model_name='accesoemergencia',
            constraint=models.UniqueConstraint(condition=models.Q(('inicio__isnull', True)), fields=('beneficiario',), name='emergencia_una_pendiente'),
        ),
        migrations.AddConstraint(
            model_name='ventanaauditoria',
            constraint=models.CheckConstraint(condition=models.Q(('abierta_en__isnull', True), ('abierta_por__isnull', False), _connector='OR'), name='ventana_apertura_con_autor'),
        ),
        migrations.AddConstraint(
            model_name='ventanaauditoria',
            constraint=models.CheckConstraint(condition=models.Q(('abierta_por', models.F('solicitada_por')), _negated=True), name='ventana_apertura_independiente'),
        ),
        migrations.AddField(
            model_name='codigounuso',
            name='emitido_por',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='codigounuso',
            name='usuario',
            field=models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='+', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddConstraint(
            model_name='codigounuso',
            constraint=models.CheckConstraint(condition=models.Q(('proposito__in', ['alta', 'recuperacion'])), name='codigo_proposito_valido'),
        ),
        migrations.AddConstraint(
            model_name='codigounuso',
            constraint=models.CheckConstraint(condition=models.Q(('huella__regex', '^[0-9a-f]{64}$')), name='codigo_huella_hex'),
        ),
        migrations.AddConstraint(
            model_name='codigounuso',
            constraint=models.CheckConstraint(condition=models.Q(('vence_en__gt', models.F('emitido_en'))), name='codigo_vence_despues'),
        ),
        migrations.AddConstraint(
            model_name='codigounuso',
            constraint=models.CheckConstraint(condition=models.Q(('intentos_fallidos__lte', 5)), name='codigo_intentos_maximos'),
        ),
        migrations.AddConstraint(
            model_name='codigounuso',
            constraint=models.UniqueConstraint(fields=('huella',), name='codigo_huella_unica'),
        ),
        migrations.RunSQL(sql=DISPARADORES, reverse_sql=QUITAR_DISPARADORES),
        migrations.RunSQL(sql=[FUNCION_VENTANA_VIGENTE], reverse_sql=[FUNCION_VENTANA_VIGENTE_ORIGINAL]),
        migrations.RunSQL(sql=[PERMISOS], reverse_sql=[QUITAR_PERMISOS]),
    ]