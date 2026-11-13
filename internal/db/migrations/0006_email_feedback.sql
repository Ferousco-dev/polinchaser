-- Delivery feedback from Resend webhooks (delivered, delayed, bounced, complained).
ALTER TABLE notification_deliveries ADD COLUMN feedback TEXT CHECK (feedback IN ('delivered','delayed','bounced','complained'));
ALTER TABLE notification_deliveries ADD COLUMN feedback_at TIMESTAMPTZ;
CREATE INDEX notification_deliveries_provider_idx ON notification_deliveries (provider_id) WHERE provider_id IS NOT NULL;

-- Webhook event ids already processed (replay protection).
CREATE TABLE resend_events (
    event_id    TEXT PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
