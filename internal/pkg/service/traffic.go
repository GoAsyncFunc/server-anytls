// Package service implements the AnyTLS node control plane and data plane.
//
// traffic.go owns the per-user byte counter that handler wrappers feed and
// reportTrafficsMonitor drains. Counters are keyed by uid (int), matching
// the v2board uniproxy report shape (UserTraffic{UID, Upload, Download}).
package service

import "sync"

// ConnStats accumulates outbound (Tx, client → upstream) and inbound (Rx,
// upstream → client) byte counts for a single user across all of their
// active streams.
type ConnStats struct {
	Tx uint64
	Rx uint64
}

// TrafficStats is a thread-safe per-user byte counter. It is reset every
// reportTrafficsInterval by GetAndReset and reported to the panel.
type TrafficStats struct {
	mu    sync.Mutex
	stats map[int]*ConnStats
}

// NewTrafficStats returns a ready-to-use counter.
func NewTrafficStats() *TrafficStats {
	return &TrafficStats{stats: make(map[int]*ConnStats)}
}

// LogTraffic adds tx and rx bytes to the user's counter. Returns false on
// no-op input (uid == 0 or both byte counts zero) so handler defer chains
// can branch on the result.
func (s *TrafficStats) LogTraffic(uid int, tx, rx uint64) bool {
	if uid == 0 || (tx == 0 && rx == 0) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.stats[uid]
	if !ok {
		c = &ConnStats{}
		s.stats[uid] = c
	}
	c.Tx += tx
	c.Rx += rx
	return true
}

// GetAndReset returns a snapshot of every accumulated counter and clears
// the internal table. Callers receive ownership of the returned map.
func (s *TrafficStats) GetAndReset() map[int]ConnStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]ConnStats, len(s.stats))
	for uid, c := range s.stats {
		out[uid] = *c
	}
	s.stats = make(map[int]*ConnStats)
	return out
}

// Len returns the number of distinct users with non-zero traffic since the
// last reset. Provided for tests and observability.
func (s *TrafficStats) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.stats)
}

// Snapshot returns a copy of the current per-user counters WITHOUT
// clearing the table. Use Snapshot + SubtractSnapshot when the report
// destination can fail: keep the snapshot in memory until the panel
// accepts the report, then atomically subtract it so concurrent
// increments arriving during the report window are preserved.
func (s *TrafficStats) Snapshot() map[int]ConnStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[int]ConnStats, len(s.stats))
	for uid, c := range s.stats {
		out[uid] = *c
	}
	return out
}

// SubtractSnapshot decrements each uid's counter by the value captured in
// snap. Entries that drop to zero are pruned. Foreign uids are ignored.
// Counters are clamped at zero so a stale snapshot can never wrap an
// unsigned counter.
func (s *TrafficStats) SubtractSnapshot(snap map[int]ConnStats) {
	if len(snap) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for uid, delta := range snap {
		c, ok := s.stats[uid]
		if !ok {
			continue
		}
		if delta.Tx >= c.Tx {
			c.Tx = 0
		} else {
			c.Tx -= delta.Tx
		}
		if delta.Rx >= c.Rx {
			c.Rx = 0
		} else {
			c.Rx -= delta.Rx
		}
		if c.Tx == 0 && c.Rx == 0 {
			delete(s.stats, uid)
		}
	}
}
