package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Ferousco-dev/polinchaser/internal/queue"
	"github.com/Ferousco-dev/polinchaser/internal/store"
	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

const (
	KindNotify = "notify"
	kindAlert  = "scan_alert"
)

type Payload struct {
	ScanID int64 `json:"scan_id"`
}

type Service struct {
	Store             *store.Store
	Sender            Sender
	From              string
	BaseURL           string
	DefaultRecipients []string
	DefaultMin        scanner.Severity
	Log               *slog.Logger
}

// Handle sends ONE grouped email per recipient for a scan, covering only
// findings that have not been alerted before. Sent recipients are skipped on
// retry, and Resend idempotency keys cover the crash-after-send window.
func (s *Service) Handle(ctx context.Context, j *queue.Job) error {
	var p Payload
	if err := json.Unmarshal(j.Payload, &p); err != nil {
		return queue.Permanent(err)
	}
	scan, err := s.Store.NotifyScan(ctx, p.ScanID)
	if errors.Is(err, store.ErrNotFound) {
		return queue.Permanent(errors.New("scan not found"))
	}
	if err != nil {
		return err
	}
	settings, err := s.Store.NotifySettings(ctx, scan.InstallationID)
	if err != nil {
		return err
	}
	if settings.Configured && !settings.Enabled {
		return nil
	}
	recipients, minSev := s.DefaultRecipients, s.DefaultMin
	if settings.Configured {
		if len(settings.Recipients) > 0 {
			recipients = settings.Recipients
		}
		minSev = scanner.Severity(settings.MinSeverity)
	}
	if len(recipients) == 0 {
		s.Log.Info("no notification recipients configured; skipping", "scan_id", scan.ScanID)
		return nil
	}
	all, err := s.Store.UnnotifiedFindings(ctx, scan.ScanID)
	if err != nil {
		return err
	}
	var findings []store.NotifyFinding
	var ids []int64
	for _, f := range all {
		if scanner.Severity(f.Severity).Rank() >= minSev.Rank() {
			findings = append(findings, f)
			ids = append(ids, f.ID)
		}
	}
	if len(findings) == 0 {
		return nil // nothing new at or above the threshold
	}
	alert := Alert{Repo: scan.RepoName, Branch: scan.Branch, Commit: scan.Commit, PRNumber: scan.PRNumber, Author: scan.Author, Time: scan.CreatedAt,
		ReportURL: fmt.Sprintf("%s/scans/%d", strings.TrimRight(s.BaseURL, "/"), scan.ScanID)}
	if s.BaseURL == "" {
		alert.ReportURL = ""
	}
	for _, f := range findings {
		alert.Findings = append(alert.Findings, AlertFinding{Path: f.Path, Line: f.Line, Title: f.Title, Severity: f.Severity, Confidence: f.Confidence, Category: f.Category})
	}
	subject, html, text, err := Render(alert)
	if err != nil {
		return queue.Permanent(err)
	}
	nid, err := s.Store.EnsureNotification(ctx, scan.InstallationID, scan.ScanID, kindAlert)
	if err != nil {
		return err
	}
	var retry error
	for _, to := range recipients {
		st, err := s.Store.DeliveryStatus(ctx, nid, to)
		if err != nil {
			return err
		}
		if st != "pending" {
			continue
		}
		sum := sha256.Sum256([]byte(to))
		key := fmt.Sprintf("pc-%d-%s", nid, hex.EncodeToString(sum[:6]))
		id, err := s.Sender.Send(ctx, Email{From: s.From, To: []string{to}, Subject: subject, HTML: html, Text: text}, key)
		var se *SendError
		switch {
		case err == nil:
			_ = s.Store.RecordDelivery(ctx, nid, to, "sent", id, "")
		case errors.As(err, &se) && !se.Retryable:
			_ = s.Store.RecordDelivery(ctx, nid, to, "failed", "", se.Error())
			s.Log.Error("email permanently rejected", "recipient_hash", key, "err", se)
		default:
			_ = s.Store.RecordDelivery(ctx, nid, to, "pending", "", err.Error())
			retry = err
		}
	}
	if retry != nil {
		return retry // queue retries with backoff; already-sent recipients are skipped
	}
	return s.Store.MarkNotified(ctx, ids)
}
