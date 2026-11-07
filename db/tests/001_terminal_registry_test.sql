-- Constraint checks for 001_terminal_registry.sql. Run after the migration; leaves no data behind.
-- psql -v ON_ERROR_STOP=1 -f db/migrations/001_terminal_registry.sql -f db/tests/001_terminal_registry_test.sql

BEGIN;

CREATE FUNCTION pg_temp.expect_fail(stmt TEXT) RETURNS VOID AS $$
BEGIN
    EXECUTE stmt;
    RAISE EXCEPTION 'expected failure, but succeeded: %', stmt;
EXCEPTION
    WHEN integrity_constraint_violation OR check_violation OR not_null_violation
      OR foreign_key_violation OR unique_violation OR invalid_text_representation THEN NULL;
END;
$$ LANGUAGE plpgsql;

INSERT INTO merchants (merchant_id) VALUES ('00000000-0000-0000-0000-00000000000a');
INSERT INTO terminals (terminal_id, merchant_id, device_serial, device_model, firmware_version, secure_element_id)
VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000000a', 'SN-A', 'PAX A920 Pro', '1.0.0', 'SE-A'),
       ('00000000-0000-0000-0000-0000000000b1', '00000000-0000-0000-0000-00000000000a', 'SN-B', 'PAX A920 Pro', '1.0.0', 'SE-B');
INSERT INTO certificates (certificate_id, terminal_id, serial_number, public_key_pem, issued_at, expires_at)
VALUES ('00000000-0000-0000-0000-0000000000c1', '00000000-0000-0000-0000-0000000000a1', 'X509-1', 'PEM', now(), now() + interval '1 year');

-- Happy path: activate terminal A with its own certificate, record a heartbeat.
UPDATE terminals SET certificate_id = '00000000-0000-0000-0000-0000000000c1', status = 'ACTIVE', activated_at = now()
WHERE terminal_id = '00000000-0000-0000-0000-0000000000a1';
INSERT INTO heartbeats (terminal_id, sent_at, signature_valid, connectivity_type, latency_ms, firmware_version, battery_level)
VALUES ('00000000-0000-0000-0000-0000000000a1', now(), true, 'CELLULAR', 42, '1.0.0', 80);

SELECT pg_temp.expect_fail($q$
    INSERT INTO terminals (merchant_id, device_serial, device_model, firmware_version, secure_element_id)
    VALUES ('00000000-0000-0000-0000-0000000000ff', 'SN-C', 'm', '1.0.0', 'se') $q$);  -- unknown merchant
SELECT pg_temp.expect_fail($q$
    INSERT INTO terminals (merchant_id, device_serial, device_model, firmware_version, secure_element_id)
    VALUES ('00000000-0000-0000-0000-00000000000a', 'SN-A', 'm', '1.0.0', 'se') $q$);  -- duplicate serial
SELECT pg_temp.expect_fail($q$
    UPDATE terminals SET status = 'ACTIVE', activated_at = now()
    WHERE terminal_id = '00000000-0000-0000-0000-0000000000b1' $q$);  -- ACTIVE without a certificate
SELECT pg_temp.expect_fail($q$
    UPDATE terminals SET certificate_id = '00000000-0000-0000-0000-0000000000c1'
    WHERE terminal_id = '00000000-0000-0000-0000-0000000000b1' $q$);  -- another terminal's certificate
SELECT pg_temp.expect_fail($q$
    UPDATE terminals SET status = 'RETIRED' WHERE terminal_id = '00000000-0000-0000-0000-0000000000b1' $q$);
SELECT pg_temp.expect_fail($q$
    INSERT INTO certificates (terminal_id, serial_number, public_key_pem, issued_at, expires_at)
    VALUES ('00000000-0000-0000-0000-0000000000b1', 'X509-2', 'PEM', now(), now() - interval '1 day') $q$);
SELECT pg_temp.expect_fail($q$
    UPDATE certificates SET revoked_at = now() WHERE serial_number = 'X509-1' $q$);  -- revoked without reason
SELECT pg_temp.expect_fail($q$
    INSERT INTO heartbeats (terminal_id, sent_at, signature_valid, connectivity_type, latency_ms, firmware_version)
    VALUES ('00000000-0000-0000-0000-0000000000a1', now(), true, 'WIFI', 1, '1.0.0') $q$);
SELECT pg_temp.expect_fail($q$
    INSERT INTO heartbeats (terminal_id, sent_at, signature_valid, connectivity_type, latency_ms, firmware_version, battery_level)
    VALUES ('00000000-0000-0000-0000-0000000000a1', now(), true, 'MESH', 1, '1.0.0', 101) $q$);

ROLLBACK;
