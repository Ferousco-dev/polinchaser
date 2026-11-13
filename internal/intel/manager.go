package intel

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Ferousco-dev/polinchaser/pkg/scanner"
)

// Manager serves the current rule set: built-in signatures plus the active
// external signatures. The version string changes whenever the external set
// changes, which makes the scheduler rescan repositories.
type Manager struct {
	Pool    *pgxpool.Pool
	Builtin scanner.RuleSet
	Log     *slog.Logger

	mu     sync.Mutex
	hash   string
	loaded bool
	rules  scanner.RuleSet
	engine *scanner.Engine
}

// Current returns the engine and version to use for a scan. If the database is
// unreachable it keeps using the last loaded rules (or the built-in set).
func (m *Manager) Current(ctx context.Context) (*scanner.Engine, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var h string
	err := m.Pool.QueryRow(ctx, `SELECT hash FROM intel_state WHERE id=1`).Scan(&h)
	if err != nil {
		if !m.loaded {
			m.set("", m.Builtin)
		}
		m.Log.Warn("intel: could not read rule state; using last known rules", "err", err)
		return m.engine, m.rules.Version
	}
	if m.loaded && h == m.hash {
		return m.engine, m.rules.Version
	}
	rs, err := m.load(ctx, h)
	if err != nil {
		m.Log.Error("intel: could not load external signatures; using last known rules", "err", err)
		if !m.loaded {
			m.set("", m.Builtin)
		}
		return m.engine, m.rules.Version
	}
	m.set(h, rs)
	return m.engine, m.rules.Version
}

// Version is the rule version a scan started now would use.
func (m *Manager) Version(ctx context.Context) string {
	_, v := m.Current(ctx)
	return v
}

func (m *Manager) set(h string, rs scanner.RuleSet) {
	m.hash, m.rules, m.engine, m.loaded = h, rs, scanner.New(rs), true
}

func (m *Manager) load(ctx context.Context, h string) (scanner.RuleSet, error) {
	if h == "" {
		return m.Builtin, nil
	}
	rows, err := m.Pool.Query(ctx, `SELECT f.id, s.sig_id, s.family, s.kind, s.value, s.severity, s.provenance
		FROM intel_signatures s JOIN intel_feeds f ON f.id = s.feed_id WHERE f.enabled ORDER BY f.id, s.sig_id`)
	if err != nil {
		return scanner.RuleSet{}, err
	}
	defer rows.Close()
	version := m.Builtin.Version + "+intel." + h[:8]
	rs := scanner.RuleSet{Version: version, Signatures: append([]scanner.Signature{}, m.Builtin.Signatures...)}
	for rows.Next() {
		var fid int64
		var id, family, kind, value, sev, prov string
		if err := rows.Scan(&fid, &id, &family, &kind, &value, &sev, &prov); err != nil {
			return scanner.RuleSet{}, err
		}
		s := scanner.Signature{ID: fmt.Sprintf("EXT-F%d-%s", fid, id), Family: family, Severity: scanner.Severity(sev),
			Provenance: "external feed: " + prov, Version: version}
		if kind == "sha256" {
			s.SHA256 = value
		} else {
			s.Substring = value
		}
		rs.Signatures = append(rs.Signatures, s)
	}
	return rs, rows.Err()
}
