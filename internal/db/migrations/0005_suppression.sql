-- Suppressions can expire; expiry reopens the finding.
ALTER TABLE findings ADD COLUMN suppressed_until TIMESTAMPTZ;
ALTER TABLE findings ADD COLUMN suppression_reason TEXT;
CREATE INDEX findings_suppression_expiry_idx ON findings (suppressed_until) WHERE suppressed_until IS NOT NULL;
