// periodic.go is a tiny ticker wrapper used by Builder for scheduled tasks
// (fetch users, report traffic, heartbeat, check node config). Close is
// idempotent via sync.Once so the lifecycle code in builder.go can call it
// without tracking which periodics have already shut down.
package service

import (
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Periodic invokes Execute every Interval. Errors returned by Execute are
// logged but never abort the loop; the executor is expected to handle its
// own retry / backoff strategy.
type Periodic struct {
	Interval time.Duration
	Execute  func() error

	stop     chan struct{}
	stopOnce sync.Once
	startMu  sync.Mutex
	started  bool
}

// Start launches the loop in a goroutine. Subsequent calls before Close
// are no-ops. Returns nil for symmetry with potential future error paths.
func (p *Periodic) Start() error {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	if p.started {
		return nil
	}
	if p.Interval <= 0 {
		return fmt.Errorf("periodic interval must be positive")
	}
	if p.Execute == nil {
		return fmt.Errorf("periodic execute function is required")
	}
	p.stop = make(chan struct{})
	p.started = true
	go p.run()
	return nil
}

func (p *Periodic) run() {
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := p.Execute(); err != nil {
				log.Errorf("Periodic task error: %v", err)
			}
		case <-p.stop:
			return
		}
	}
}

// Close terminates the loop. Safe to call zero or many times — the second
// and later calls return immediately without panicking on a closed channel.
func (p *Periodic) Close() {
	p.stopOnce.Do(func() {
		if p.stop != nil {
			close(p.stop)
		}
	})
}
