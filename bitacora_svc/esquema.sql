-- Esquema de la base de bitácora. Lo aplica la cuenta propietaria de ESA base (bit_migrador) con
-- scripts/aplicar_esquema_bitacora.py, que reemplaza __ESQUEMA__ por un nombre validado.
--
-- Tablas de solo anexar: los disparadores rechazan UPDATE, DELETE y TRUNCATE para cualquier rol,
-- incluido el propietario. bit_rw (la cuenta del servicio) solo tiene USAGE, SELECT e INSERT; nunca
-- CREATE. Ninguna función es SECURITY DEFINER y todas fijan search_path.

CREATE SCHEMA __ESQUEMA__;
REVOKE ALL ON SCHEMA __ESQUEMA__ FROM PUBLIC;
GRANT USAGE ON SCHEMA __ESQUEMA__ TO bit_rw;

CREATE TABLE __ESQUEMA__.evento (
    seq bigint PRIMARY KEY CHECK (seq >= 1),
    sello timestamptz NOT NULL,
    clase varchar(20) NOT NULL
        CHECK (clase IN ('certificacion', 'consulta', 'acceso', 'administracion')),
    usuario char(32) CHECK (usuario IS NULL OR usuario ~ '^[0-9a-f]{32}$'),
    objeto_tipo varchar(20),
    objeto_id varchar(64),
    -- JSON canónico exacto del evento sin hash ni hash_previo: de él se recalcula el hash.
    cuerpo text NOT NULL CHECK (octet_length(cuerpo) <= 20000),
    hash_previo char(64) NOT NULL CHECK (hash_previo ~ '^[0-9a-f]{64}$'),
    hash char(64) NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX evento_usuario ON __ESQUEMA__.evento (usuario, seq);
CREATE INDEX evento_objeto ON __ESQUEMA__.evento (objeto_tipo, objeto_id, seq);
CREATE INDEX evento_clase_sello ON __ESQUEMA__.evento (clase, sello);

CREATE TABLE __ESQUEMA__.punto (
    seq bigint PRIMARY KEY REFERENCES __ESQUEMA__.evento (seq),
    hash char(64) NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
    fecha timestamptz NOT NULL,
    key_id char(16) NOT NULL CHECK (key_id ~ '^[0-9a-f]{16}$'),
    documento text NOT NULL
);

CREATE FUNCTION __ESQUEMA__.rechazar_modificacion() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
        MESSAGE = format('Bitácora de solo anexar: %s no está permitido sobre %s.', TG_OP, TG_TABLE_NAME);
END;
$$;

-- Defensa en profundidad: aunque el servicio calcula todo, la base exige seq contiguo, hash previo
-- igual al hash del último evento, sello que no retrocede y hash bien calculado.
CREATE FUNCTION __ESQUEMA__.evento_encadenado() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    v_seq bigint;
    v_hash text;
    v_sello timestamptz;
BEGIN
    SELECT e.seq, e.hash, e.sello INTO v_seq, v_hash, v_sello
      FROM __ESQUEMA__.evento e ORDER BY e.seq DESC LIMIT 1;
    IF NEW.seq IS DISTINCT FROM coalesce(v_seq, 0) + 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Bitácora: la secuencia debe ser contigua.';
    END IF;
    IF NEW.hash_previo IS DISTINCT FROM coalesce(v_hash, repeat('0', 64)) THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Bitácora: el hash previo no es el del último evento.';
    END IF;
    IF v_sello IS NOT NULL AND NEW.sello < v_sello THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Bitácora: el sello de tiempo no puede retroceder.';
    END IF;
    IF NEW.hash IS DISTINCT FROM encode(sha256(convert_to(NEW.hash_previo || NEW.cuerpo, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION USING ERRCODE = 'integrity_constraint_violation',
            MESSAGE = 'Bitácora: el hash no corresponde al evento.';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evento_encadenado BEFORE INSERT ON __ESQUEMA__.evento
    FOR EACH ROW EXECUTE FUNCTION __ESQUEMA__.evento_encadenado();
CREATE TRIGGER evento_inmutable BEFORE UPDATE OR DELETE ON __ESQUEMA__.evento
    FOR EACH ROW EXECUTE FUNCTION __ESQUEMA__.rechazar_modificacion();
CREATE TRIGGER evento_sin_truncate BEFORE TRUNCATE ON __ESQUEMA__.evento
    FOR EACH STATEMENT EXECUTE FUNCTION __ESQUEMA__.rechazar_modificacion();
CREATE TRIGGER punto_inmutable BEFORE UPDATE OR DELETE ON __ESQUEMA__.punto
    FOR EACH ROW EXECUTE FUNCTION __ESQUEMA__.rechazar_modificacion();
CREATE TRIGGER punto_sin_truncate BEFORE TRUNCATE ON __ESQUEMA__.punto
    FOR EACH STATEMENT EXECUTE FUNCTION __ESQUEMA__.rechazar_modificacion();

REVOKE ALL ON ALL TABLES IN SCHEMA __ESQUEMA__ FROM PUBLIC;
GRANT SELECT, INSERT ON __ESQUEMA__.evento, __ESQUEMA__.punto TO bit_rw;
REVOKE ALL ON FUNCTION __ESQUEMA__.rechazar_modificacion(), __ESQUEMA__.evento_encadenado() FROM PUBLIC;
