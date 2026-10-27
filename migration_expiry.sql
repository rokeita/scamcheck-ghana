-- ScamCheck Ghana — expiry migration (v1)
-- Applies on top of schema.sql. Safe to run twice (IF NOT EXISTS guards
-- where Postgres supports them; the constraint changes are guarded by
-- DO blocks).

-- 1. phone_numbers: fresh-review date, lapse audit, counting cycle,
--    and the interval behind F (so a qualifying new report can restart
--    the clock by a full period without inventing a policy duration).
ALTER TABLE phone_numbers
    ADD COLUMN IF NOT EXISTS fresh_review_date timestamptz,
    ADD COLUMN IF NOT EXISTS fresh_review_interval interval,
    ADD COLUMN IF NOT EXISTS lapsed_at timestamptz,
    ADD COLUMN IF NOT EXISTS flag_cycle integer NOT NULL DEFAULT 1;

-- 2. reports: which cycle a report belongs to
ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS cycle integer NOT NULL DEFAULT 1;

-- Backfill: everything so far is cycle 1 (already the default).

-- 3. Duplicate guard becomes per-cycle: one report per user per number
--    PER CYCLE, so a lapsed reporter may report again in a new cycle.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'reports_phone_number_id_reporter_id_key'
    ) THEN
        ALTER TABLE reports
            DROP CONSTRAINT reports_phone_number_id_reporter_id_key;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'reports_phone_number_reporter_cycle_key'
    ) THEN
        ALTER TABLE reports
            ADD CONSTRAINT reports_phone_number_reporter_cycle_key
            UNIQUE (phone_number_id, reporter_id, cycle);
    END IF;
END $$;

-- 4. disputes.status gains 'inconclusive' (review ended without a verdict).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'disputes_status_check'
    ) THEN
        ALTER TABLE disputes DROP CONSTRAINT disputes_status_check;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'disputes_status_check'
    ) THEN
        ALTER TABLE disputes ADD CONSTRAINT disputes_status_check
            CHECK (status IN ('pending', 'upheld', 'rejected', 'inconclusive'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS phone_numbers_expiry_idx
    ON phone_numbers (risk_status, fresh_review_date)
    WHERE fresh_review_date IS NOT NULL;
