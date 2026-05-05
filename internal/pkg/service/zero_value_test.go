package service

import "testing"

func TestTrafficStats_ZeroValueLogTraffic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value LogTraffic panicked: %v", r)
		}
	}()

	var s TrafficStats
	if !s.LogTraffic(7, 10, 20) {
		t.Fatal("LogTraffic(7,10,20) should return true")
	}
	got := s.Snapshot()
	if got[7].Tx != 10 || got[7].Rx != 20 {
		t.Errorf("snapshot=%+v want Tx=10 Rx=20", got[7])
	}
	if s.Len() != 1 {
		t.Errorf("Len=%d want 1", s.Len())
	}
}

func TestTrafficStats_ZeroValueSnapshotAndSubtract(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value Snapshot/Subtract panicked: %v", r)
		}
	}()

	var s TrafficStats
	_ = s.Snapshot()
	s.SubtractSnapshot(map[int]ConnStats{1: {Tx: 1, Rx: 1}})
	if s.Len() != 0 {
		t.Errorf("Len=%d want 0", s.Len())
	}
}

func TestTrafficStats_ZeroValueGetAndReset(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value GetAndReset panicked: %v", r)
		}
	}()

	var s TrafficStats
	got := s.GetAndReset()
	if len(got) != 0 {
		t.Errorf("zero-value GetAndReset = %d entries, want 0", len(got))
	}
}

func TestOnlineTracker_ZeroValueMark(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value Mark panicked: %v", r)
		}
	}()

	var tr OnlineTracker
	tr.Mark(7, "1.2.3.4")
	if tr.Len() != 1 {
		t.Errorf("Len=%d want 1", tr.Len())
	}
	snap := tr.Snapshot()
	if len(snap[7]) == 0 {
		t.Errorf("snapshot[7]=%v want at least one IP", snap[7])
	}
	tr.Unmark(7, "1.2.3.4")
	if tr.Len() != 0 {
		t.Errorf("after Unmark Len=%d want 0", tr.Len())
	}
}

func TestOnlineTracker_ZeroValueUnmarkOnly(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value Unmark panicked: %v", r)
		}
	}()

	var tr OnlineTracker
	tr.Unmark(7, "1.2.3.4")
}

func TestBuilder_CloseBeforeStartIsSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value Builder.Close panicked: %v", r)
		}
	}()

	var b Builder
	if err := b.Close(); err != nil {
		t.Errorf("Close(zero)=%v want nil", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("Close(zero) second call=%v want nil", err)
	}
}
