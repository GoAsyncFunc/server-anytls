// online.go tracks the active set of {uid, source IP} pairs across all
// in-flight streams. heartbeatMonitor reports Snapshot() to the panel via
// uniproxy ReportNodeOnlineUsers. Reference counting keeps the same IP
// listed across overlapping streams from one client.
package service

import "sync"

// OnlineTracker maps uid → ip → live-stream refcount.
type OnlineTracker struct {
	mu    sync.Mutex
	table map[int]map[string]int
}

// NewOnlineTracker returns an empty tracker.
func NewOnlineTracker() *OnlineTracker {
	return &OnlineTracker{table: make(map[int]map[string]int)}
}

// Mark records that uid has an additional active stream from ip. Calling
// it for the same {uid, ip} pair n times requires n matching Unmark calls
// to fully clear that pair. uid == 0 or empty ip are ignored.
func (t *OnlineTracker) Mark(uid int, ip string) {
	if uid == 0 || ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.table == nil {
		t.table = make(map[int]map[string]int)
	}
	ips, ok := t.table[uid]
	if !ok {
		ips = make(map[string]int)
		t.table[uid] = ips
	}
	ips[ip]++
}

// Unmark drops one reference for {uid, ip}. The pair is fully removed when
// its refcount falls to zero; the user entry is deleted when no IPs remain.
// Calling Unmark for a missing pair is a no-op.
func (t *OnlineTracker) Unmark(uid int, ip string) {
	if uid == 0 || ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	ips, ok := t.table[uid]
	if !ok {
		return
	}
	if ips[ip] <= 1 {
		delete(ips, ip)
	} else {
		ips[ip]--
	}
	if len(ips) == 0 {
		delete(t.table, uid)
	}
}

// Snapshot returns a deep copy of the current uid → []ip mapping in the
// shape expected by uniproxy.Client.ReportNodeOnlineUsers.
func (t *OnlineTracker) Snapshot() map[int][]string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[int][]string, len(t.table))
	for uid, ips := range t.table {
		list := make([]string, 0, len(ips))
		for ip := range ips {
			list = append(list, ip)
		}
		out[uid] = list
	}
	return out
}

// Len returns the number of distinct uids currently online. For tests and
// observability.
func (t *OnlineTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.table)
}
