// Package limiter provides per-user bandwidth rate limiting backed by a
// token-bucket registry keyed on the v2board uid (int).
//
// Builder maintains the registry when user lists change; the inbound
// handler consults it at connection setup to wrap the data links. One
// bucket per user is shared across uplink and downlink, so a user limit
// of N Mbps is a cap on total throughput in either direction, matching
// typical v2board semantics.
package limiter

import (
	"sync"
	"time"

	"github.com/juju/ratelimit"
)

// bitsPerMbps converts the v2board Mbps value to bytes/sec
// (1_000_000 bits / 8).
const bitsPerMbps = 1_000_000 / 8

type entry struct {
	mbps   int
	bucket *ratelimit.Bucket
}

var (
	mu      sync.RWMutex
	buckets = map[int]*entry{}
)

// Set registers the per-user speed limit. mbps <= 0 is treated as
// "no limit" and removes any existing entry. If the limit is unchanged
// the bucket is left intact so in-flight connections keep a stable rate.
func Set(uid int, mbps int) {
	if uid <= 0 {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if mbps <= 0 {
		delete(buckets, uid)
		return
	}
	if e, ok := buckets[uid]; ok && e.mbps == mbps {
		return
	}
	bps := int64(mbps) * bitsPerMbps
	buckets[uid] = &entry{
		mbps:   mbps,
		bucket: ratelimit.NewBucketWithQuantum(time.Second, bps, bps),
	}
}

// Remove drops any bucket for the user. Safe to call when no entry exists.
func Remove(uid int) {
	if uid <= 0 {
		return
	}
	mu.Lock()
	delete(buckets, uid)
	mu.Unlock()
}

// Bucket returns the bucket for the user, or nil if the user has no
// limit. Callers should cache the returned value for the lifetime of a
// connection rather than looking it up per packet.
func Bucket(uid int) *ratelimit.Bucket {
	if uid <= 0 {
		return nil
	}
	mu.RLock()
	e, ok := buckets[uid]
	mu.RUnlock()
	if !ok {
		return nil
	}
	return e.bucket
}

// Reset clears the entire registry. Intended for tests.
func Reset() {
	mu.Lock()
	buckets = map[int]*entry{}
	mu.Unlock()
}
