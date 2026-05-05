package service

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeriodic_StartFiresExecute(t *testing.T) {
	calls := make(chan struct{}, 2)
	p := &Periodic{
		Interval: time.Millisecond,
		Execute: func() error {
			select {
			case calls <- struct{}{}:
			default:
			}
			return nil
		},
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	for i := 0; i < 2; i++ {
		select {
		case <-calls:
		case <-time.After(time.Second):
			t.Fatalf("Execute called %d times, want 2", i)
		}
	}
}

func TestPeriodic_CloseIdempotent(t *testing.T) {
	p := &Periodic{
		Interval: time.Millisecond,
		Execute:  func() error { return nil },
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	p.Close()
	p.Close() // must not panic
	p.Close()
}

func TestPeriodic_CloseUnstarted(t *testing.T) {
	p := &Periodic{}
	p.Close() // must not panic on never-started instance
}

func TestPeriodic_StartTwice(t *testing.T) {
	var calls atomic.Int64
	p := &Periodic{
		Interval: 5 * time.Millisecond,
		Execute: func() error {
			calls.Add(1)
			return nil
		},
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start (2nd): %v", err)
	}
	defer p.Close()

	time.Sleep(30 * time.Millisecond)
	if calls.Load() == 0 {
		t.Error("Execute never called")
	}
}

func TestPeriodic_ExecuteErrorDoesNotStopLoop(t *testing.T) {
	var calls atomic.Int64
	p := &Periodic{
		Interval: 3 * time.Millisecond,
		Execute: func() error {
			calls.Add(1)
			return errors.New("boom")
		},
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	time.Sleep(20 * time.Millisecond)
	if calls.Load() < 3 {
		t.Errorf("Execute called %d, want >=3 even after errors", calls.Load())
	}
}

func TestPeriodic_RejectsZeroIntervalAndNilExecute(t *testing.T) {
	p1 := &Periodic{Interval: 0, Execute: func() error { return nil }}
	if err := p1.Start(); err == nil {
		t.Fatal("Start zero-interval should fail")
	}
	p1.Close()

	p2 := &Periodic{Interval: time.Millisecond, Execute: nil}
	if err := p2.Start(); err == nil {
		t.Fatal("Start nil-Execute should fail")
	}
	p2.Close()
}
