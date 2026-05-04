package service

import (
	"sync"
	"testing"
)

func TestTrafficStats_LogAndReset(t *testing.T) {
	s := NewTrafficStats()
	if !s.LogTraffic(7, 100, 50) {
		t.Fatal("LogTraffic returned false for valid input")
	}
	s.LogTraffic(7, 1, 2)
	s.LogTraffic(8, 10, 20)

	snap := s.GetAndReset()
	if got := snap[7]; got.Tx != 101 || got.Rx != 52 {
		t.Errorf("uid=7 stats = %+v, want Tx=101 Rx=52", got)
	}
	if got := snap[8]; got.Tx != 10 || got.Rx != 20 {
		t.Errorf("uid=8 stats = %+v, want Tx=10 Rx=20", got)
	}
	if s.Len() != 0 {
		t.Errorf("Len after reset = %d, want 0", s.Len())
	}
}

func TestTrafficStats_LogTraffic_Noop(t *testing.T) {
	cases := []struct {
		name      string
		uid       int
		tx, rx    uint64
		want      bool
		wantStats int
	}{
		{"zero uid", 0, 1, 1, false, 0},
		{"zero bytes", 5, 0, 0, false, 0},
		{"only tx", 5, 10, 0, true, 1},
		{"only rx", 6, 0, 10, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewTrafficStats()
			got := s.LogTraffic(tc.uid, tc.tx, tc.rx)
			if got != tc.want {
				t.Errorf("LogTraffic(%d,%d,%d) = %v, want %v",
					tc.uid, tc.tx, tc.rx, got, tc.want)
			}
			if s.Len() != tc.wantStats {
				t.Errorf("Len = %d, want %d", s.Len(), tc.wantStats)
			}
		})
	}
}

func TestTrafficStats_Concurrent(t *testing.T) {
	s := NewTrafficStats()
	const workers = 16
	const perWorker = 1000
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				s.LogTraffic(1, 1, 1)
			}
		}()
	}
	wg.Wait()

	snap := s.GetAndReset()
	want := uint64(workers * perWorker)
	if got := snap[1]; got.Tx != want || got.Rx != want {
		t.Errorf("Tx=%d Rx=%d, want both %d", got.Tx, got.Rx, want)
	}
}

func TestTrafficStats_GetAndReset_Empty(t *testing.T) {
	s := NewTrafficStats()
	snap := s.GetAndReset()
	if len(snap) != 0 {
		t.Errorf("empty GetAndReset = %d entries, want 0", len(snap))
	}
}

func TestTrafficStats_GetAndReset_OwnsCopy(t *testing.T) {
	s := NewTrafficStats()
	s.LogTraffic(3, 5, 5)
	snap := s.GetAndReset()
	snap[3] = ConnStats{Tx: 999, Rx: 999}
	s.LogTraffic(3, 1, 1)
	snap2 := s.GetAndReset()
	if snap2[3].Tx != 1 || snap2[3].Rx != 1 {
		t.Errorf("internal state polluted by snapshot mutation: %+v", snap2[3])
	}
}
