// traffic_preserve_test.go pins the post-fix invariant that traffic
// counters must NOT be lost when the panel report fails. The current
// reportTrafficsMonitor calls GetAndReset before the API call, so a
// network/HTTP failure permanently drops that window of bytes. After
// the fix:
//
//   - Snapshot()        → returns counters without clearing the table
//   - SubtractSnapshot  → atomically subtracts a previously-snapshotted
//                         value once the report has been accepted
//
// During the gap between Snapshot and Subtract, more traffic may
// accumulate; subtraction must preserve those increments.
package service

import "testing"

func TestTrafficStats_SnapshotDoesNotReset(t *testing.T) {
	s := NewTrafficStats()
	s.LogTraffic(7, 100, 200)
	snap := s.Snapshot()
	if snap[7].Tx != 100 || snap[7].Rx != 200 {
		t.Fatalf("snapshot = %+v, want Tx=100 Rx=200", snap[7])
	}
	// Counter must still be reachable after Snapshot.
	again := s.Snapshot()
	if again[7].Tx != 100 || again[7].Rx != 200 {
		t.Errorf("Snapshot should not reset; got %+v", again[7])
	}
}

func TestTrafficStats_SubtractSnapshotRetainsConcurrentDelta(t *testing.T) {
	s := NewTrafficStats()
	s.LogTraffic(7, 100, 200)
	snap := s.Snapshot()

	// Simulate traffic arriving WHILE the report is being delivered.
	s.LogTraffic(7, 30, 40)

	s.SubtractSnapshot(snap)

	// After subtract, only the concurrent-delta bytes should remain.
	left := s.Snapshot()
	if left[7].Tx != 30 || left[7].Rx != 40 {
		t.Errorf("after subtract residual = %+v, want Tx=30 Rx=40", left[7])
	}
}

func TestTrafficStats_SubtractSnapshotPrunesZeroEntries(t *testing.T) {
	s := NewTrafficStats()
	s.LogTraffic(9, 50, 60)
	snap := s.Snapshot()
	s.SubtractSnapshot(snap)

	if got := s.Len(); got != 0 {
		t.Errorf("after full subtract Len()=%d, want 0", got)
	}
}

func TestTrafficStats_SubtractSnapshotIgnoresMissingUID(t *testing.T) {
	s := NewTrafficStats()
	s.LogTraffic(9, 1, 2)
	// snapshot a foreign uid that's not in the table.
	foreign := map[int]ConnStats{42: {Tx: 999, Rx: 999}}
	s.SubtractSnapshot(foreign)
	left := s.Snapshot()
	if left[9].Tx != 1 || left[9].Rx != 2 {
		t.Errorf("uid=9 must remain untouched, got %+v", left[9])
	}
	if _, ok := left[42]; ok {
		t.Errorf("foreign uid must not be created by Subtract")
	}
}
