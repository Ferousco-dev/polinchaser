package auth

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter is a per-key sliding-window limiter held in memory. With several
// web instances each enforces its own window; for a single operator
// dashboard that is an acceptable trade-off and is documented.
type Limiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
	now    func() time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{window: window, max: max, hits: map[string][]time.Time{}, now: time.Now}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cut := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	if len(l.hits) > 10000 { // bound memory under address-spraying
		for k, v := range l.hits {
			if len(v) == 0 || !v[len(v)-1].After(cut) {
				delete(l.hits, k)
			}
		}
	}
	return true
}

// ClientIP returns the caller address. X-Forwarded-For is only honoured when
// the operator declares how many trusted proxy hops append to it; the entry
// that many positions from the right is used so clients cannot spoof it.
func ClientIP(r *http.Request, trustedHops int) string {
	if trustedHops > 0 {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if i := len(parts) - trustedHops; i >= 0 && i < len(parts) {
			if ip := strings.TrimSpace(parts[i]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
