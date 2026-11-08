-- Step 27: certification test harness runs. A scheme certification (migration 014) can be recorded for a model and
-- firmware only if the latest harness run for that exact pair passed and covered that scheme. A later failing run
-- blocks new approvals until the firmware passes again. The report is the evidence: masked PAN, no chip data values.

BEGIN;

CREATE TABLE certification_runs (
    run_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_model      VARCHAR NOT NULL,
    firmware_version  VARCHAR NOT NULL,
    driver            VARCHAR NOT NULL,  -- what drove the terminal: "software" or a device driver
    passed            BOOLEAN NOT NULL,  -- derived from the report's cases, never taken from the caller
    schemes           VARCHAR[] NOT NULL,
    report            JSONB NOT NULL,
    recorded_by       VARCHAR NOT NULL,
    recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX certification_runs_latest ON certification_runs (device_model, firmware_version, recorded_at DESC);

COMMIT;
