package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	maxWebhookBody   = 1 << 20
	webhookTolerance = 5 * time.Minute
)

// ParseWebhookSecret decodes a Resend signing secret ("whsec_" + base64).
func ParseWebhookSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "whsec_") {
		return nil, errors.New("webhook secret must start with whsec_")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "whsec_"))
	if err != nil || len(key) < 16 {
		return nil, errors.New("webhook secret is not valid")
	}
	return key, nil
}

// WebhookHandler receives Resend delivery events. Resend signs webhooks with the Svix
// scheme: HMAC-SHA256 over "<svix-id>.<svix-timestamp>.<raw body>". Requests with a bad or
// stale signature are rejected before anything is read from the body.
type WebhookHandler struct {
	Key  []byte
	Pool *pgxpool.Pool
	Log  *slog.Logger
	Now  func() time.Time
}

var feedbackByEvent = map[string]string{
	"email.delivered":        "delivered",
	"email.delivery_delayed": "delayed",
	"email.bounced":          "bounced",
	"email.complained":       "complained",
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now
	if h.Now != nil {
		now = h.Now
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	id, ts, sigs := r.Header.Get("svix-id"), r.Header.Get("svix-timestamp"), r.Header.Get("svix-signature")
	if id == "" || ts == "" || sigs == "" || len(id) > 128 {
		http.Error(w, "missing signature headers", http.StatusBadRequest)
		return
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || now().Sub(time.Unix(sec, 0)).Abs() > webhookTolerance {
		http.Error(w, "timestamp outside tolerance", http.StatusBadRequest)
		return
	}
	if !h.verify(id, ts, body, sigs) {
		h.Log.Warn("resend webhook: bad signature")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var ev struct {
		Type string `json:"type"`
		Data struct {
			EmailID string `json:"email_id"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &ev) != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	feedback, relevant := feedbackByEvent[ev.Type]
	if !relevant || ev.Data.EmailID == "" || len(ev.Data.EmailID) > 128 {
		w.WriteHeader(http.StatusNoContent) // events we do not track (sent, opened, clicked...)
		return
	}
	ctx := r.Context()
	tag, err := h.Pool.Exec(ctx, `INSERT INTO resend_events (event_id) VALUES ($1) ON CONFLICT DO NOTHING`, id)
	if err != nil {
		h.Log.Error("resend webhook: dedupe insert failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError) // Resend will retry
		return
	}
	if tag.RowsAffected() == 0 {
		w.WriteHeader(http.StatusNoContent) // already processed
		return
	}
	// A later "delivered" must not hide an earlier bounce or complaint.
	_, err = h.Pool.Exec(ctx, `UPDATE notification_deliveries SET feedback=$2, feedback_at=now(),
		last_error = CASE WHEN $2 IN ('bounced','complained') THEN $2 ELSE last_error END
		WHERE provider_id=$1 AND COALESCE(feedback,'') NOT IN ('bounced','complained')`, ev.Data.EmailID, feedback)
	if err != nil {
		_, _ = h.Pool.Exec(ctx, `DELETE FROM resend_events WHERE event_id=$1`, id) // let the retry reprocess
		h.Log.Error("resend webhook: update failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if feedback == "bounced" || feedback == "complained" {
		h.Log.Warn("alert email "+feedback, "provider_id", ev.Data.EmailID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *WebhookHandler) verify(id, ts string, body []byte, header string) bool {
	mac := hmac.New(sha256.New, h.Key)
	mac.Write([]byte(id + "." + ts + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	ok := false
	for _, part := range strings.Fields(header) {
		v, sig, found := strings.Cut(part, ",")
		if !found || v != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err == nil && hmac.Equal(got, want) { // no early exit: constant work per signature
			ok = true
		}
	}
	return ok
}
