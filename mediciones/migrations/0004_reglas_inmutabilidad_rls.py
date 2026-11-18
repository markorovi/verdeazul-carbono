"""Parámetros de política, inmutabilidad, reglas H1 y H3, y RLS de mediciones.

Solo PostgreSQL. Se ejecuta con el rol migrador, dueño de los objetos. Ninguna función es
SECURITY DEFINER: los disparadores y las políticas corren con los permisos (y la RLS) de quien
invoca, y todas fijan search_path.
"""

from django.db import migrations

ERROR = "integrity_constraint_violation"

PARAMETROS = [
    ("valto_tco2e", "500", "Volumen (t CO2e) sobre el cual se exigen dos aprobadores distintos (H1)"),
    ("tenm_dias", "90", "Plazo en días desde el cierre del período para solicitar enmiendas (Cd11)"),
    ("wc_horas", "24", "Ventana corta de H2, en horas"),
    ("wl_dias", "30", "Ventana larga de H2, en días"),
    ("h2_wc_laboral_blando", "10", "H2: umbral blando en Wc, horario laboral"),
    ("h2_wc_laboral_duro", "25", "H2: umbral duro en Wc, horario laboral"),
    ("h2_wc_fuera_blando", "3", "H2: umbral blando en Wc, fuera de horario"),
    ("h2_wc_fuera_duro", "8", "H2: umbral duro en Wc, fuera de horario"),
    ("h2_wl_blando", "40", "H2: umbral blando en Wl"),
    ("h2_wl_duro", "100", "H2: umbral duro en Wl"),
]

TABLAS_INMUTABLES = ["mediciones_politicaparametro", "mediciones_medicionversion", "mediciones_aprobacion"]
TABLAS_SIN_BORRADO = ["mediciones_medicion", "mediciones_enmienda", "mediciones_certificado", "mediciones_alerta"]
TABLAS_RLS = [
    "mediciones_medicion",
    "mediciones_medicionversion",
    "mediciones_aprobacion",
    "mediciones_enmienda",
    "mediciones_certificado",
]


def _funcion(nombre: str, cuerpo: str, declaraciones: str = "") -> str:
    """Función de disparador plpgsql con search_path fijo y sin SECURITY DEFINER."""
    return f"""
CREATE FUNCTION {nombre}() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
{declaraciones}
BEGIN
{cuerpo}
END;
$$
"""


def _error(mensaje_sql: str) -> str:
    return f"RAISE EXCEPTION USING ERRCODE = '{ERROR}', MESSAGE = {mensaje_sql};"


# --------------------------------------------------------------------------- inmutabilidad

FUNCION_RECHAZAR = _funcion(
    "mediciones_rechazar_modificacion",
    "    " + _error("format('Inmutabilidad: %s no está permitido sobre %s.', TG_OP, TG_TABLE_NAME)"),
)


def _triggers_inmutables(tabla: str) -> list[str]:
    return [
        f"CREATE TRIGGER {tabla}_inmutable BEFORE UPDATE OR DELETE ON {tabla}"
        " FOR EACH ROW EXECUTE FUNCTION mediciones_rechazar_modificacion()",
        f"CREATE TRIGGER {tabla}_sin_truncate BEFORE TRUNCATE ON {tabla}"
        " FOR EACH STATEMENT EXECUTE FUNCTION mediciones_rechazar_modificacion()",
    ]


def _triggers_sin_borrado(tabla: str) -> list[str]:
    return [
        f"CREATE TRIGGER {tabla}_sin_borrado BEFORE DELETE ON {tabla}"
        " FOR EACH ROW EXECUTE FUNCTION mediciones_rechazar_modificacion()",
        f"CREATE TRIGGER {tabla}_sin_truncate BEFORE TRUNCATE ON {tabla}"
        " FOR EACH STATEMENT EXECUTE FUNCTION mediciones_rechazar_modificacion()",
    ]


INMUTABILIDAD = (
    [FUNCION_RECHAZAR]
    + [s for t in TABLAS_INMUTABLES for s in _triggers_inmutables(t)]
    + [s for t in TABLAS_SIN_BORRADO for s in _triggers_sin_borrado(t)]
)
QUITAR_INMUTABILIDAD = (
    [f"DROP TRIGGER {t}_inmutable ON {t}" for t in TABLAS_INMUTABLES]
    + [f"DROP TRIGGER {t}_sin_borrado ON {t}" for t in TABLAS_SIN_BORRADO]
    + [f"DROP TRIGGER {t}_sin_truncate ON {t}" for t in TABLAS_INMUTABLES + TABLAS_SIN_BORRADO]
    + ["DROP FUNCTION mediciones_rechazar_modificacion()"]
)

# --------------------------------------------------------------------------- utilidades

FUNCION_HUELLA = """
CREATE FUNCTION mediciones_calcular_huella(
    p_medicion uuid, p_numero integer, p_co2e numeric, p_fecha date,
    p_notas text, p_creada_por uuid, p_previa text
) RETURNS text
LANGUAGE sql
STABLE
SET search_path = public
AS $$
    SELECT encode(sha256(convert_to(concat_ws('|',
        p_medicion::text, p_numero::text, p_co2e::text, to_char(p_fecha, 'YYYY-MM-DD'),
        coalesce(p_notas, ''), p_creada_por::text, coalesce(p_previa, '')), 'UTF8')), 'hex')
$$
"""

FUNCION_PARAMETRO = """
CREATE FUNCTION mediciones_parametro(p_clave text) RETURNS numeric
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
DECLARE
    v_valor numeric;
BEGIN
    SELECT valor INTO v_valor FROM mediciones_politicaparametro WHERE clave = p_clave;
    IF v_valor IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = format('Falta el parámetro de política %s.', p_clave);
    END IF;
    RETURN v_valor;
END;
$$
"""

UTILIDADES = [FUNCION_HUELLA, FUNCION_PARAMETRO]
QUITAR_UTILIDADES = [
    "DROP FUNCTION mediciones_parametro(text)",
    "DROP FUNCTION mediciones_calcular_huella(uuid, integer, numeric, date, text, uuid, text)",
]

# --------------------------------------------------------------------------- medición

FUNCION_MEDICION_REGISTRO = _funcion(
    "mediciones_medicion_registro",
    f"""
    IF NEW.estado <> 'borrador' OR NEW.ciclo <> 1 OR NEW.devuelta_por_id IS NOT NULL THEN
        {_error("'Registro rechazado: una medición nueva empieza en borrador, ciclo 1 y sin devolución.'")}
    END IF;
    SELECT estado INTO v_periodo FROM mediciones_periodo WHERE id = NEW.periodo_id FOR SHARE;
    IF v_periodo IS DISTINCT FROM 'abierto' THEN
        {_error("'Registro rechazado (Cd5): el período no está abierto.'")}
    END IF;
    NEW.creada_en := now();
    RETURN NEW;""",
    "DECLARE\n    v_periodo text;",
)

FUNCION_MEDICION_TRANSICION = _funcion(
    "mediciones_medicion_transicion",
    f"""
    IF NEW.id <> OLD.id OR NEW.parcela_id <> OLD.parcela_id OR NEW.periodo_id <> OLD.periodo_id
       OR NEW.registrada_por_id <> OLD.registrada_por_id OR NEW.creada_en IS DISTINCT FROM OLD.creada_en THEN
        {_error("'Medición: solo pueden cambiar estado, ciclo y devuelta_por.'")}
    END IF;
    v_anulacion := OLD.estado = 'certificada' AND NEW.estado = 'presentada';
    IF NEW.ciclo <> OLD.ciclo AND NOT (v_anulacion AND NEW.ciclo = OLD.ciclo + 1) THEN
        {_error("'Medición: el ciclo solo sube de uno en uno al anular el certificado (certificada a presentada).'")}
    END IF;
    IF v_anulacion AND NEW.ciclo <> OLD.ciclo + 1 THEN
        {_error("'Medición: al volver de certificada a presentada el ciclo debe subir en 1.'")}
    END IF;
    IF NEW.devuelta_por_id IS DISTINCT FROM OLD.devuelta_por_id AND NEW.estado <> 'devuelta' THEN
        {_error("'Medición: devuelta_por solo cambia al devolver la medición.'")}
    END IF;
    IF NEW.estado = OLD.estado THEN
        RETURN NEW;
    END IF;

    SELECT estado INTO v_periodo FROM mediciones_periodo WHERE id = NEW.periodo_id FOR SHARE;

    IF OLD.estado = 'borrador' AND NEW.estado = 'presentada' THEN
        IF v_periodo <> 'abierto' THEN
            {_error("'Transición rechazada (Cd5): solo se presenta con el período abierto.'")}
        END IF;
        IF NOT EXISTS (SELECT 1 FROM mediciones_medicionversion WHERE medicion_id = NEW.id) THEN
            {_error("'Transición rechazada: no se presenta una medición sin versiones.'")}
        END IF;
    ELSIF OLD.estado = 'borrador' AND NEW.estado = 'sin_presentar' THEN
        IF v_periodo <> 'cerrado' THEN
            {_error("'Transición rechazada: una medición queda sin presentar solo al cerrar el período.'")}
        END IF;
    ELSIF OLD.estado = 'presentada' AND NEW.estado = 'devuelta' THEN
        IF v_periodo <> 'cerrado' THEN
            {_error("'Transición rechazada (Cd7): solo se devuelve con el período cerrado.'")}
        END IF;
        IF NEW.devuelta_por_id IS NULL THEN
            {_error("'Transición rechazada: devolver exige indicar devuelta_por.'")}
        END IF;
    ELSIF OLD.estado = 'presentada' AND NEW.estado = 'aprobada' THEN
        IF v_periodo <> 'cerrado' THEN
            {_error("'Transición rechazada (Cd7): solo se aprueba con el período cerrado.'")}
        END IF;
        IF NOT EXISTS (SELECT 1 FROM mediciones_aprobacion WHERE medicion_id = NEW.id AND ciclo = NEW.ciclo) THEN
            {_error("'Transición rechazada: aprobada exige una aprobación registrada en el ciclo.'")}
        END IF;
    ELSIF OLD.estado = 'aprobada' AND NEW.estado = 'certificada' THEN
        IF NOT EXISTS (SELECT 1 FROM mediciones_certificado
                        WHERE medicion_id = NEW.id AND ciclo = NEW.ciclo AND estado = 'vigente') THEN
            {_error("'Transición rechazada (H1): certificada exige un certificado vigente del ciclo.'")}
        END IF;
    ELSIF OLD.estado = 'certificada' AND NEW.estado = 'presentada' THEN
        IF NOT EXISTS (SELECT 1 FROM mediciones_certificado
                        WHERE medicion_id = NEW.id AND ciclo = OLD.ciclo AND estado = 'anulado')
           OR EXISTS (SELECT 1 FROM mediciones_certificado
                       WHERE medicion_id = NEW.id AND ciclo = OLD.ciclo AND estado = 'vigente') THEN
            {_error("'Transición rechazada: solo vuelve a presentada si el certificado del ciclo está anulado.'")}
        END IF;
    ELSIF OLD.estado = 'sin_presentar' AND NEW.estado = 'presentada' THEN
        SELECT enmienda_id INTO v_enmienda FROM mediciones_medicionversion
         WHERE medicion_id = NEW.id ORDER BY numero DESC LIMIT 1;
        IF v_enmienda IS NULL THEN
            {_error("'Transición rechazada (Cd11): una medición sin presentar solo se presenta con una versión de enmienda.'")}
        END IF;
    ELSIF (OLD.estado = 'aprobada' AND NEW.estado = 'presentada')
       OR (OLD.estado = 'devuelta' AND NEW.estado = 'presentada') THEN
        NULL;
    ELSE
        {_error("format('Transición no permitida: %s a %s.', OLD.estado, NEW.estado)")}
    END IF;
    RETURN NEW;""",
    "DECLARE\n    v_periodo text;\n    v_anulacion boolean;\n    v_enmienda uuid;",
)

FUNCION_PERIODO_CIERRE = _funcion(
    "mediciones_periodo_cierre",
    """
    -- Corre con la RLS del actor que cierra: solo marca las mediciones que ese actor puede actualizar.
    UPDATE mediciones_medicion SET estado = 'sin_presentar'
     WHERE periodo_id = NEW.id AND estado = 'borrador';
    RETURN NULL;""",
)

MEDICION = [
    FUNCION_MEDICION_REGISTRO,
    "CREATE TRIGGER mediciones_medicion_registro BEFORE INSERT ON mediciones_medicion"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_medicion_registro()",
    FUNCION_MEDICION_TRANSICION,
    "CREATE TRIGGER mediciones_medicion_transicion BEFORE UPDATE ON mediciones_medicion"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_medicion_transicion()",
    FUNCION_PERIODO_CIERRE,
    "CREATE TRIGGER mediciones_periodo_cierre AFTER UPDATE ON mediciones_periodo FOR EACH ROW"
    " WHEN (OLD.estado = 'abierto' AND NEW.estado = 'cerrado')"
    " EXECUTE FUNCTION mediciones_periodo_cierre()",
]
QUITAR_MEDICION = [
    "DROP TRIGGER mediciones_periodo_cierre ON mediciones_periodo",
    "DROP FUNCTION mediciones_periodo_cierre()",
    "DROP TRIGGER mediciones_medicion_transicion ON mediciones_medicion",
    "DROP FUNCTION mediciones_medicion_transicion()",
    "DROP TRIGGER mediciones_medicion_registro ON mediciones_medicion",
    "DROP FUNCTION mediciones_medicion_registro()",
]

# --------------------------------------------------------------------------- versiones

FUNCION_VERSION = _funcion(
    "mediciones_version_registro",
    f"""
    SELECT * INTO v_medicion FROM mediciones_medicion WHERE id = NEW.medicion_id FOR UPDATE;
    IF NOT FOUND THEN
        {_error("'Versión rechazada: la medición no existe o el actor no puede modificarla.'")}
    END IF;
    SELECT numero, huella INTO v_ultimo, v_previa FROM mediciones_medicionversion
     WHERE medicion_id = NEW.medicion_id ORDER BY numero DESC LIMIT 1;
    IF NEW.numero IS DISTINCT FROM coalesce(v_ultimo, 0) + 1 THEN
        {_error("format('Versión rechazada: el número debe ser %s (consecutivo).', coalesce(v_ultimo, 0) + 1)")}
    END IF;
    IF NEW.enmienda_id IS NULL THEN
        SELECT estado INTO v_periodo FROM mediciones_periodo WHERE id = v_medicion.periodo_id FOR SHARE;
        IF v_medicion.estado <> 'borrador' THEN
            {_error("'Versión rechazada (AM-01): sin enmienda solo se agregan versiones a mediciones en borrador.'")}
        END IF;
        IF v_periodo <> 'abierto' THEN
            {_error("'Versión rechazada (Cd5): el período está cerrado; los cambios requieren una enmienda.'")}
        END IF;
        IF NEW.creada_por_id <> v_medicion.registrada_por_id THEN
            {_error("'Versión rechazada (Cd6): solo quien registró la medición crea sus versiones.'")}
        END IF;
    ELSE
        SELECT * INTO v_enmienda FROM mediciones_enmienda WHERE id = NEW.enmienda_id;
        IF NOT FOUND OR v_enmienda.medicion_id <> NEW.medicion_id THEN
            {_error("'Versión rechazada: la enmienda no corresponde a esta medición.'")}
        END IF;
        IF v_enmienda.estado <> 'autorizada' THEN
            {_error("'Versión rechazada (Cd12): la enmienda no está autorizada.'")}
        END IF;
        IF EXISTS (SELECT 1 FROM mediciones_medicionversion WHERE enmienda_id = NEW.enmienda_id) THEN
            {_error("'Versión rechazada: la enmienda ya se usó.'")}
        END IF;
        IF NEW.co2e_toneladas <> v_enmienda.co2e_nuevo OR NEW.fecha_muestreo <> v_enmienda.fecha_nueva
           OR NEW.notas IS DISTINCT FROM v_enmienda.notas_nuevas THEN
            {_error("'Versión rechazada: los valores deben ser exactamente los autorizados en la enmienda.'")}
        END IF;
        IF NEW.creada_por_id <> v_enmienda.solicitante_id THEN
            {_error("'Versión rechazada: la versión de una enmienda se crea a nombre de su solicitante.'")}
        END IF;
    END IF;
    NEW.creada_en := now();
    NEW.huella_previa := v_previa;
    NEW.huella := mediciones_calcular_huella(NEW.medicion_id, NEW.numero, NEW.co2e_toneladas,
        NEW.fecha_muestreo, NEW.notas, NEW.creada_por_id, v_previa);
    RETURN NEW;""",
    "DECLARE\n    v_medicion mediciones_medicion%ROWTYPE;\n    v_enmienda mediciones_enmienda%ROWTYPE;"
    "\n    v_periodo text;\n    v_ultimo integer;\n    v_previa text;",
)

VERSIONES = [
    FUNCION_VERSION,
    "CREATE TRIGGER mediciones_version_registro BEFORE INSERT ON mediciones_medicionversion"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_version_registro()",
]
QUITAR_VERSIONES = [
    "DROP TRIGGER mediciones_version_registro ON mediciones_medicionversion",
    "DROP FUNCTION mediciones_version_registro()",
]

# --------------------------------------------------------------------------- aprobaciones

FUNCION_APROBACION = _funcion(
    "mediciones_aprobacion_registro",
    f"""
    SELECT * INTO v_medicion FROM mediciones_medicion WHERE id = NEW.medicion_id FOR UPDATE;
    IF NOT FOUND THEN
        {_error("'Aprobación rechazada: la medición no existe o el actor no puede modificarla.'")}
    END IF;
    IF v_medicion.estado NOT IN ('presentada', 'aprobada') THEN
        {_error("'Aprobación rechazada: la medición debe estar presentada o con una aprobación pendiente.'")}
    END IF;
    SELECT estado INTO v_periodo FROM mediciones_periodo WHERE id = v_medicion.periodo_id;
    IF v_periodo <> 'cerrado' THEN
        {_error("'Aprobación rechazada (Cd7): solo se aprueba con el período cerrado.'")}
    END IF;
    SELECT * INTO v_version FROM mediciones_medicionversion
     WHERE medicion_id = NEW.medicion_id ORDER BY numero DESC LIMIT 1;
    IF NOT FOUND OR NEW.version_id <> v_version.id THEN
        {_error("'Aprobación rechazada: solo se aprueba la última versión de la medición.'")}
    END IF;
    IF NEW.ciclo <> v_medicion.ciclo THEN
        {_error("'Aprobación rechazada: el ciclo no coincide con el de la medición.'")}
    END IF;
    IF NEW.aprobador_id = v_medicion.registrada_por_id
       OR (v_medicion.devuelta_por_id IS NOT NULL AND NEW.aprobador_id = v_medicion.devuelta_por_id)
       OR EXISTS (SELECT 1 FROM mediciones_medicionversion
                   WHERE medicion_id = NEW.medicion_id AND creada_por_id = NEW.aprobador_id) THEN
        {_error("'Aprobación rechazada (Cd8): quien registró, modificó o devolvió la medición no puede aprobarla.'")}
    END IF;
    NEW.huella_aprobada := v_version.huella;
    NEW.aprobada_en := now();
    RETURN NEW;""",
    "DECLARE\n    v_medicion mediciones_medicion%ROWTYPE;\n    v_version mediciones_medicionversion%ROWTYPE;"
    "\n    v_periodo text;",
)

FUNCION_APROBACION_APLICAR = _funcion(
    "mediciones_aprobacion_aplicar",
    """
    UPDATE mediciones_medicion SET estado = 'aprobada' WHERE id = NEW.medicion_id AND estado = 'presentada';
    RETURN NULL;""",
)

APROBACIONES = [
    FUNCION_APROBACION,
    "CREATE TRIGGER mediciones_aprobacion_registro BEFORE INSERT ON mediciones_aprobacion"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_aprobacion_registro()",
    FUNCION_APROBACION_APLICAR,
    "CREATE TRIGGER mediciones_aprobacion_aplicar AFTER INSERT ON mediciones_aprobacion"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_aprobacion_aplicar()",
]
QUITAR_APROBACIONES = [
    "DROP TRIGGER mediciones_aprobacion_aplicar ON mediciones_aprobacion",
    "DROP FUNCTION mediciones_aprobacion_aplicar()",
    "DROP TRIGGER mediciones_aprobacion_registro ON mediciones_aprobacion",
    "DROP FUNCTION mediciones_aprobacion_registro()",
]

# --------------------------------------------------------------------------- enmiendas

FUNCION_ENMIENDA_SOLICITUD = _funcion(
    "mediciones_enmienda_solicitud",
    f"""
    SELECT * INTO v_medicion FROM mediciones_medicion WHERE id = NEW.medicion_id;
    IF NOT FOUND THEN
        {_error("'Enmienda rechazada: la medición no existe o no es visible para el actor.'")}
    END IF;
    SELECT estado, cerrado_en INTO v_periodo, v_cerrado_en FROM mediciones_periodo WHERE id = v_medicion.periodo_id;
    IF v_periodo <> 'cerrado' THEN
        {_error("'Enmienda rechazada (Cd11): solo se enmiendan mediciones con el período cerrado.'")}
    END IF;
    v_tenm := mediciones_parametro('tenm_dias');
    IF now() - v_cerrado_en > make_interval(days => v_tenm::integer)
       AND NOT (
           NOT EXISTS (SELECT 1 FROM mediciones_certificado WHERE medicion_id = NEW.medicion_id AND estado = 'vigente')
           AND EXISTS (SELECT 1 FROM mediciones_certificado WHERE medicion_id = NEW.medicion_id AND estado = 'anulado')
       ) THEN
        {_error("format('Enmienda rechazada (Cd11): vencieron los %s días desde el cierre y la medición no tiene un certificado anulado sin uno vigente.', v_tenm::integer)")}
    END IF;
    IF NOT (NEW.solicitante_id = v_medicion.registrada_por_id
            OR (v_medicion.devuelta_por_id IS NOT NULL AND NEW.solicitante_id = v_medicion.devuelta_por_id)
            OR EXISTS (SELECT 1 FROM mediciones_aprobacion
                        WHERE medicion_id = NEW.medicion_id AND aprobador_id = NEW.solicitante_id)) THEN
        {_error("'Enmienda rechazada (Cd11): el solicitante no registró, aprobó ni devolvió la medición.'")}
    END IF;
    IF NEW.version_base_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM mediciones_medicionversion WHERE id = NEW.version_base_id AND medicion_id = NEW.medicion_id) THEN
        {_error("'Enmienda rechazada: la versión base no pertenece a la medición.'")}
    END IF;
    NEW.estado := 'solicitada';
    NEW.autorizador_id := NULL;
    NEW.resuelta_en := NULL;
    NEW.solicitada_en := now();
    RETURN NEW;""",
    "DECLARE\n    v_medicion mediciones_medicion%ROWTYPE;\n    v_periodo text;\n    v_cerrado_en timestamptz;"
    "\n    v_tenm numeric;",
)

FUNCION_ENMIENDA_RESOLUCION = _funcion(
    "mediciones_enmienda_resolucion",
    f"""
    IF NEW.id <> OLD.id OR NEW.medicion_id <> OLD.medicion_id
       OR NEW.version_base_id IS DISTINCT FROM OLD.version_base_id OR NEW.solicitante_id <> OLD.solicitante_id
       OR NEW.motivo <> OLD.motivo OR NEW.co2e_nuevo <> OLD.co2e_nuevo OR NEW.fecha_nueva <> OLD.fecha_nueva
       OR NEW.notas_nuevas IS DISTINCT FROM OLD.notas_nuevas OR NEW.solicitada_en <> OLD.solicitada_en THEN
        {_error("'Enmienda: solo pueden cambiar estado, autorizador y resuelta_en.'")}
    END IF;
    IF NOT (OLD.estado = 'solicitada' AND NEW.estado IN ('autorizada', 'rechazada')) THEN
        {_error("'Enmienda: solo se resuelve (autoriza o rechaza) una enmienda solicitada.'")}
    END IF;
    SELECT registrada_por_id INTO v_registrante FROM mediciones_medicion WHERE id = OLD.medicion_id;
    IF NEW.autorizador_id = OLD.solicitante_id OR NEW.autorizador_id = v_registrante
       OR EXISTS (SELECT 1 FROM mediciones_aprobacion
                   WHERE medicion_id = OLD.medicion_id AND aprobador_id = NEW.autorizador_id) THEN
        {_error("'Enmienda rechazada (Cd12): el autorizador debe ser distinto del solicitante, del registrante y de todo aprobador.'")}
    END IF;
    NEW.resuelta_en := now();
    RETURN NEW;""",
    "DECLARE\n    v_registrante uuid;",
)

ENMIENDAS = [
    FUNCION_ENMIENDA_SOLICITUD,
    "CREATE TRIGGER mediciones_enmienda_solicitud BEFORE INSERT ON mediciones_enmienda"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_enmienda_solicitud()",
    FUNCION_ENMIENDA_RESOLUCION,
    "CREATE TRIGGER mediciones_enmienda_resolucion BEFORE UPDATE ON mediciones_enmienda"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_enmienda_resolucion()",
]
QUITAR_ENMIENDAS = [
    "DROP TRIGGER mediciones_enmienda_resolucion ON mediciones_enmienda",
    "DROP FUNCTION mediciones_enmienda_resolucion()",
    "DROP TRIGGER mediciones_enmienda_solicitud ON mediciones_enmienda",
    "DROP FUNCTION mediciones_enmienda_solicitud()",
]

# --------------------------------------------------------------------------- certificados

FUNCION_CERTIFICADO_EMISION = _funcion(
    "mediciones_certificado_emision",
    f"""
    SELECT * INTO v_medicion FROM mediciones_medicion WHERE id = NEW.medicion_id FOR UPDATE;
    IF NOT FOUND THEN
        {_error("'Certificado rechazado: la medición no existe o el actor no puede modificarla.'")}
    END IF;
    IF NEW.parcela_id <> v_medicion.parcela_id OR NEW.periodo_id <> v_medicion.periodo_id THEN
        {_error("'Certificado rechazado (H1): parcela y período deben ser los de la medición.'")}
    END IF;
    IF NEW.estado <> 'vigente' THEN
        {_error("'Certificado rechazado: un certificado se emite vigente.'")}
    END IF;
    IF v_medicion.estado <> 'aprobada' THEN
        {_error("'Certificado rechazado (H1, Cd10): la medición debe estar aprobada.'")}
    END IF;
    SELECT estado INTO v_periodo FROM mediciones_periodo WHERE id = v_medicion.periodo_id;
    IF v_periodo <> 'cerrado' THEN
        {_error("'Certificado rechazado (H1): el período debe estar cerrado.'")}
    END IF;
    SELECT * INTO v_version FROM mediciones_medicionversion
     WHERE medicion_id = NEW.medicion_id ORDER BY numero DESC LIMIT 1;
    IF NOT FOUND OR NEW.version_id <> v_version.id THEN
        {_error("'Certificado rechazado (H1): debe certificar la última versión de la medición.'")}
    END IF;
    IF NEW.ciclo <> v_medicion.ciclo THEN
        {_error("'Certificado rechazado (H1): el ciclo no coincide con el de la medición.'")}
    END IF;
    SELECT count(DISTINCT aprobador_id) INTO v_aprobadores FROM mediciones_aprobacion
     WHERE medicion_id = NEW.medicion_id AND ciclo = v_medicion.ciclo
       AND version_id = v_version.id AND huella_aprobada = v_version.huella;
    IF v_aprobadores < 1 THEN
        {_error("'Certificado rechazado (H1): falta una aprobación de esta versión en el ciclo actual.'")}
    END IF;
    v_valto := mediciones_parametro('valto_tco2e');
    IF v_version.co2e_toneladas > v_valto AND v_aprobadores < 2 THEN
        {_error("format('Certificado rechazado (H1): más de %s t CO2e exige dos aprobadores distintos.', v_valto)")}
    END IF;
    NEW.emitido_en := now();
    RETURN NEW;""",
    "DECLARE\n    v_medicion mediciones_medicion%ROWTYPE;\n    v_version mediciones_medicionversion%ROWTYPE;"
    "\n    v_periodo text;\n    v_aprobadores integer;\n    v_valto numeric;",
)

FUNCION_CERTIFICADO_APLICAR_EMISION = _funcion(
    "mediciones_certificado_aplicar_emision",
    """
    UPDATE mediciones_medicion SET estado = 'certificada' WHERE id = NEW.medicion_id;
    RETURN NULL;""",
)

FUNCION_CERTIFICADO_ANULACION = _funcion(
    "mediciones_certificado_anulacion",
    f"""
    IF NEW.id <> OLD.id OR NEW.parcela_id <> OLD.parcela_id OR NEW.periodo_id <> OLD.periodo_id
       OR NEW.medicion_id <> OLD.medicion_id OR NEW.version_id <> OLD.version_id OR NEW.ciclo <> OLD.ciclo
       OR NEW.emitido_en <> OLD.emitido_en THEN
        {_error("'Certificado: solo pueden cambiar el estado y los datos de anulación.'")}
    END IF;
    IF NOT (OLD.estado = 'vigente' AND NEW.estado = 'anulado') THEN
        {_error("'Certificado: solo se permite anular un certificado vigente.'")}
    END IF;
    IF EXISTS (SELECT 1 FROM mediciones_aprobacion
                WHERE medicion_id = OLD.medicion_id AND version_id = OLD.version_id
                  AND aprobador_id = NEW.anulado_por_id) THEN
        {_error("'Anulación rechazada (Cd20): quien aprobó la versión no puede anular su certificado.'")}
    END IF;
    NEW.anulado_en := now();
    RETURN NEW;""",
)

FUNCION_CERTIFICADO_APLICAR_ANULACION = _funcion(
    "mediciones_certificado_aplicar_anulacion",
    """
    UPDATE mediciones_medicion SET estado = 'presentada', ciclo = ciclo + 1 WHERE id = NEW.medicion_id;
    RETURN NULL;""",
)

CERTIFICADOS = [
    FUNCION_CERTIFICADO_EMISION,
    "CREATE TRIGGER mediciones_certificado_emision BEFORE INSERT ON mediciones_certificado"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_certificado_emision()",
    FUNCION_CERTIFICADO_APLICAR_EMISION,
    "CREATE TRIGGER mediciones_certificado_aplicar_emision AFTER INSERT ON mediciones_certificado"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_certificado_aplicar_emision()",
    FUNCION_CERTIFICADO_ANULACION,
    "CREATE TRIGGER mediciones_certificado_anulacion BEFORE UPDATE ON mediciones_certificado"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_certificado_anulacion()",
    FUNCION_CERTIFICADO_APLICAR_ANULACION,
    "CREATE TRIGGER mediciones_certificado_aplicar_anulacion AFTER UPDATE ON mediciones_certificado"
    " FOR EACH ROW WHEN (OLD.estado = 'vigente' AND NEW.estado = 'anulado')"
    " EXECUTE FUNCTION mediciones_certificado_aplicar_anulacion()",
]
QUITAR_CERTIFICADOS = [
    "DROP TRIGGER mediciones_certificado_aplicar_anulacion ON mediciones_certificado",
    "DROP FUNCTION mediciones_certificado_aplicar_anulacion()",
    "DROP TRIGGER mediciones_certificado_anulacion ON mediciones_certificado",
    "DROP FUNCTION mediciones_certificado_anulacion()",
    "DROP TRIGGER mediciones_certificado_aplicar_emision ON mediciones_certificado",
    "DROP FUNCTION mediciones_certificado_aplicar_emision()",
    "DROP TRIGGER mediciones_certificado_emision ON mediciones_certificado",
    "DROP FUNCTION mediciones_certificado_emision()",
]

# --------------------------------------------------------------------------- alertas

FUNCION_ALERTA = _funcion(
    "mediciones_alerta_resolucion",
    f"""
    IF NEW.id <> OLD.id OR NEW.tipo <> OLD.tipo OR NEW.prioridad <> OLD.prioridad
       OR NEW.usuario_id IS DISTINCT FROM OLD.usuario_id OR NEW.parcela_id IS DISTINCT FROM OLD.parcela_id
       OR NEW.medicion_id IS DISTINCT FROM OLD.medicion_id OR NEW.detalle IS DISTINCT FROM OLD.detalle
       OR NEW.creada_en <> OLD.creada_en THEN
        {_error("'Alerta: solo pueden cambiar resuelta_en y resuelta_por.'")}
    END IF;
    IF OLD.resuelta_en IS NOT NULL THEN
        {_error("'Alerta: ya fue resuelta; no se vuelve a resolver.'")}
    END IF;
    NEW.resuelta_en := now();
    RETURN NEW;""",
)

ALERTAS = [
    FUNCION_ALERTA,
    "CREATE TRIGGER mediciones_alerta_resolucion BEFORE UPDATE ON mediciones_alerta"
    " FOR EACH ROW EXECUTE FUNCTION mediciones_alerta_resolucion()",
]
QUITAR_ALERTAS = [
    "DROP TRIGGER mediciones_alerta_resolucion ON mediciones_alerta",
    "DROP FUNCTION mediciones_alerta_resolucion()",
]

# --------------------------------------------------------------------------- funciones de RLS


def _funcion_sql(firma: str, retorno: str, cuerpo: str) -> str:
    return f"""
CREATE FUNCTION {firma} RETURNS {retorno}
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
{cuerpo}
$$
"""


FUNCIONES_RLS = [
    _funcion_sql(
        "app_usuario_actual()",
        "uuid",
        # Valor ausente, vacío o con formato no UUID: NULL sin lanzar error (falla cerrado).
        "    SELECT CASE WHEN v ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'\n"
        "                THEN v::uuid END\n"
        "      FROM (SELECT current_setting('app.usuario_id', true) AS v) AS s",
    ),
    _funcion_sql(
        "app_tiene_rol(p_codigo text)",
        "boolean",
        "    SELECT EXISTS (SELECT 1 FROM usuarios_rolusuario\n"
        "                    WHERE usuario_id = app_usuario_actual() AND rol_id = p_codigo AND hasta IS NULL)",
    ),
    _funcion_sql(
        "app_es_dueno_de_parcela(p_parcela uuid)",
        "boolean",
        "    SELECT EXISTS (SELECT 1 FROM catalogo_parcela pa\n"
        "                     JOIN catalogo_propiedad pr ON pr.finca_id = pa.finca_id\n"
        "                    WHERE pa.id = p_parcela AND pr.dueno_id = app_usuario_actual() AND pr.hasta IS NULL)",
    ),
    _funcion_sql(
        "app_ventana_auditoria_vigente()",
        "boolean",
        "    SELECT EXISTS (SELECT 1 FROM usuarios_ventanaauditoria\n"
        "                    WHERE auditor_id = app_usuario_actual() AND inicio <= now() AND now() < fin)",
    ),
    _funcion_sql(
        "app_tecnico_asignado(p_parcela uuid)",
        "boolean",
        "    SELECT EXISTS (SELECT 1 FROM catalogo_asignacion\n"
        "                    WHERE tecnico_id = app_usuario_actual() AND parcela_id = p_parcela\n"
        "                      AND desde <= now() AND now() < hasta)",
    ),
    _funcion_sql(
        "app_puede_ver_parcela(p_parcela uuid)",
        "boolean",
        "    SELECT app_usuario_actual() IS NOT NULL AND CASE\n"
        "        WHEN app_tiene_rol('R6') THEN app_es_dueno_de_parcela(p_parcela)\n"
        "        WHEN app_tiene_rol('R5') THEN app_ventana_auditoria_vigente()\n"
        "        ELSE true\n"
        "    END",
    ),
    _funcion_sql(
        "app_puede_ver_medicion(p_medicion uuid)",
        "boolean",
        "    SELECT EXISTS (SELECT 1 FROM mediciones_medicion\n"
        "                    WHERE id = p_medicion AND app_puede_ver_parcela(parcela_id))",
    ),
]
QUITAR_FUNCIONES_RLS = [
    "DROP FUNCTION app_puede_ver_medicion(uuid)",
    "DROP FUNCTION app_puede_ver_parcela(uuid)",
    "DROP FUNCTION app_tecnico_asignado(uuid)",
    "DROP FUNCTION app_ventana_auditoria_vigente()",
    "DROP FUNCTION app_es_dueno_de_parcela(uuid)",
    "DROP FUNCTION app_tiene_rol(text)",
    "DROP FUNCTION app_usuario_actual()",
]

ACTIVAR_RLS = [s for t in TABLAS_RLS for s in (
    f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY",
    f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY",
)]
DESACTIVAR_RLS = [s for t in TABLAS_RLS for s in (
    f"ALTER TABLE {t} NO FORCE ROW LEVEL SECURITY",
    f"ALTER TABLE {t} DISABLE ROW LEVEL SECURITY",
)]

ACTOR = "app_usuario_actual()"
POLITICAS = [
    ("mediciones_medicion", "medicion_lectura", "SELECT", "USING (app_puede_ver_parcela(parcela_id))"),
    ("mediciones_medicion", "medicion_registro", "INSERT",
     f"WITH CHECK (registrada_por_id = {ACTOR} AND app_tiene_rol('R1') AND app_tecnico_asignado(parcela_id))"),
    ("mediciones_medicion", "medicion_cambio", "UPDATE",
     f"USING (app_tiene_rol('R2') OR app_tiene_rol('R7') OR (app_tiene_rol('R1') AND registrada_por_id = {ACTOR}))"
     f" WITH CHECK (app_tiene_rol('R2') OR app_tiene_rol('R7') OR (app_tiene_rol('R1') AND registrada_por_id = {ACTOR}))"),
    ("mediciones_medicionversion", "version_lectura", "SELECT", "USING (app_puede_ver_medicion(medicion_id))"),
    # Sin enmienda, la versión es del propio técnico; con enmienda, también puede cargarla un R7.
    ("mediciones_medicionversion", "version_registro", "INSERT",
     f"WITH CHECK ((app_tiene_rol('R1') AND creada_por_id = {ACTOR})"
     " OR (app_tiene_rol('R7') AND enmienda_id IS NOT NULL))"),
    ("mediciones_aprobacion", "aprobacion_lectura", "SELECT", "USING (app_puede_ver_medicion(medicion_id))"),
    ("mediciones_aprobacion", "aprobacion_registro", "INSERT",
     f"WITH CHECK (app_tiene_rol('R2') AND aprobador_id = {ACTOR})"),
    ("mediciones_enmienda", "enmienda_lectura", "SELECT", "USING (app_puede_ver_medicion(medicion_id))"),
    ("mediciones_enmienda", "enmienda_solicitud", "INSERT",
     f"WITH CHECK ((app_tiene_rol('R1') OR app_tiene_rol('R2')) AND solicitante_id = {ACTOR})"),
    ("mediciones_enmienda", "enmienda_resolucion", "UPDATE",
     f"USING (app_tiene_rol('R7')) WITH CHECK (app_tiene_rol('R7') AND autorizador_id = {ACTOR})"),
    ("mediciones_certificado", "certificado_lectura", "SELECT", "USING (app_puede_ver_parcela(parcela_id))"),
    ("mediciones_certificado", "certificado_emision", "INSERT", "WITH CHECK (app_tiene_rol('R2'))"),
    ("mediciones_certificado", "certificado_anulacion", "UPDATE",
     f"USING (app_tiene_rol('R7')) WITH CHECK (app_tiene_rol('R7') AND anulado_por_id = {ACTOR})"),
]

PERMISOS_APP_RW = [
    "GRANT SELECT ON mediciones_politicaparametro TO app_rw",
    "GRANT SELECT, INSERT ON mediciones_medicion TO app_rw",
    "GRANT UPDATE (estado, ciclo, devuelta_por_id) ON mediciones_medicion TO app_rw",
    "GRANT SELECT, INSERT ON mediciones_medicionversion TO app_rw",
    "GRANT SELECT, INSERT ON mediciones_aprobacion TO app_rw",
    "GRANT SELECT, INSERT ON mediciones_enmienda TO app_rw",
    "GRANT UPDATE (estado, autorizador_id, resuelta_en) ON mediciones_enmienda TO app_rw",
    "GRANT SELECT, INSERT ON mediciones_certificado TO app_rw",
    "GRANT UPDATE (estado, anulado_en, anulado_por_id, justificacion_anulacion) ON mediciones_certificado TO app_rw",
    "GRANT SELECT, INSERT ON mediciones_alerta TO app_rw",
    "GRANT UPDATE (resuelta_en, resuelta_por_id) ON mediciones_alerta TO app_rw",
]

TABLAS_NUEVAS = ["mediciones_politicaparametro", "mediciones_alerta"] + TABLAS_RLS


def _bloque_app_rw(sentencias: list[str]) -> str:
    """Bloque que solo corre si existe el rol app_rw (sin él, nadie ve filas: falla cerrado)."""
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


POLITICAS_Y_PERMISOS = _bloque_app_rw(
    [f"CREATE POLICY {n} ON {t} AS PERMISSIVE FOR {c} TO app_rw {e}" for t, n, c, e in POLITICAS]
    + PERMISOS_APP_RW
)
QUITAR_POLITICAS_Y_PERMISOS = _bloque_app_rw(
    [f"DROP POLICY IF EXISTS {n} ON {t}" for t, n, _, _ in POLITICAS]
    + [f"REVOKE ALL ON {t} FROM app_rw" for t in TABLAS_NUEVAS]
)


class Migration(migrations.Migration):
    dependencies = [
        ("mediciones", "0003_nucleo_mediciones"),
        ("catalogo", "0002_geometria_reglas_y_permisos"),
        ("usuarios", "0003_autenticacion_totp"),
    ]

    operations = [
        migrations.RunSQL(
            sql=[
                (
                    "INSERT INTO mediciones_politicaparametro (clave, valor, descripcion) VALUES (%s, %s, %s)",
                    [clave, valor, descripcion],
                )
                for clave, valor, descripcion in PARAMETROS
            ],
            reverse_sql=["DELETE FROM mediciones_politicaparametro"],
        ),
        migrations.RunSQL(sql=INMUTABILIDAD, reverse_sql=QUITAR_INMUTABILIDAD),
        migrations.RunSQL(sql=UTILIDADES, reverse_sql=QUITAR_UTILIDADES),
        migrations.RunSQL(sql=MEDICION, reverse_sql=QUITAR_MEDICION),
        migrations.RunSQL(sql=VERSIONES, reverse_sql=QUITAR_VERSIONES),
        migrations.RunSQL(sql=APROBACIONES, reverse_sql=QUITAR_APROBACIONES),
        migrations.RunSQL(sql=ENMIENDAS, reverse_sql=QUITAR_ENMIENDAS),
        migrations.RunSQL(sql=CERTIFICADOS, reverse_sql=QUITAR_CERTIFICADOS),
        migrations.RunSQL(sql=ALERTAS, reverse_sql=QUITAR_ALERTAS),
        migrations.RunSQL(sql=FUNCIONES_RLS, reverse_sql=QUITAR_FUNCIONES_RLS),
        migrations.RunSQL(sql=ACTIVAR_RLS, reverse_sql=DESACTIVAR_RLS),
        migrations.RunSQL(sql=[POLITICAS_Y_PERMISOS], reverse_sql=[QUITAR_POLITICAS_Y_PERMISOS]),
    ]
