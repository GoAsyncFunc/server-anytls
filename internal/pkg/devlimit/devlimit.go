// Package devlimit enforces per-user device-count caps. The v2board
// UserInfo.DeviceLimit field is interpreted as the maximum number of
// distinct source IPs allowed to connect concurrently for one user.
//
// device_limit <= 0 means "no limit". Reference counting keeps the same
// IP eligible across overlapping streams from one client without
// double-counting.
package devlimit

import "sync"

type tracker struct {
	quota int            // 0 == unlimited
	ips   map[string]int // ip → live-stream refcount
}

var (
	mu    sync.Mutex
	users = map[int]*tracker{}
)

// SetQuota records the device limit for a user. quota <= 0 disables the
// cap (existing tracked IPs are kept so live connections survive a
// quota-relaxation; a fresh tracker is allocated on the next Acquire).
func SetQuota(uid int, quota int) {
	if uid <= 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	t, ok := users[uid]
	if !ok {
		users[uid] = &tracker{quota: quota, ips: make(map[string]int)}
		return
	}
	t.quota = quota
}

// RemoveUser drops all state for a user. Use when the user disappears
// from the panel.
func RemoveUser(uid int) {
	if uid <= 0 {
		return
	}
	mu.Lock()
	delete(users, uid)
	mu.Unlock()
}

// Acquire records that {uid, ip} has one more active stream. Returns
// false when the new IP would exceed the user's quota — caller must
// reject the connection. uid <= 0 or empty ip count as success without
// tracking, matching the "no limit" code path.
func Acquire(uid int, ip string) bool {
	if uid <= 0 || ip == "" {
		return true
	}
	mu.Lock()
	defer mu.Unlock()
	t, ok := users[uid]
	if !ok {
		t = &tracker{ips: make(map[string]int)}
		users[uid] = t
	}
	if _, exists := t.ips[ip]; exists {
		t.ips[ip]++
		return true
	}
	if t.quota > 0 && len(t.ips) >= t.quota {
		return false
	}
	t.ips[ip] = 1
	return true
}

// Release drops one reference for {uid, ip}. The IP is removed when its
// refcount hits zero. Calling Release for an unknown pair is a safe no-op.
func Release(uid int, ip string) {
	if uid <= 0 || ip == "" {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	t, ok := users[uid]
	if !ok {
		return
	}
	count, ok := t.ips[ip]
	if !ok {
		return
	}
	if count <= 1 {
		delete(t.ips, ip)
	} else {
		t.ips[ip]--
	}
}

// ActiveIPs returns the number of distinct IPs currently tracked for a
// user. For tests and observability.
func ActiveIPs(uid int) int {
	if uid <= 0 {
		return 0
	}
	mu.Lock()
	defer mu.Unlock()
	t, ok := users[uid]
	if !ok {
		return 0
	}
	return len(t.ips)
}

// Reset clears the entire registry. Intended for tests.
func Reset() {
	mu.Lock()
	users = map[int]*tracker{}
	mu.Unlock()
}
