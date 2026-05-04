package service

import (
	"sort"
	"sync"
	"testing"
)

func TestOnlineTracker_MarkSnapshot(t *testing.T) {
	tr := NewOnlineTracker()
	tr.Mark(1, "1.1.1.1")
	tr.Mark(1, "2.2.2.2")
	tr.Mark(2, "3.3.3.3")

	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot users = %d, want 2", len(snap))
	}
	got1 := append([]string(nil), snap[1]...)
	sort.Strings(got1)
	want1 := []string{"1.1.1.1", "2.2.2.2"}
	if len(got1) != len(want1) || got1[0] != want1[0] || got1[1] != want1[1] {
		t.Errorf("uid=1 ips = %v, want %v", got1, want1)
	}
	if got := snap[2]; len(got) != 1 || got[0] != "3.3.3.3" {
		t.Errorf("uid=2 ips = %v, want [3.3.3.3]", got)
	}
}

func TestOnlineTracker_UnmarkRefcount(t *testing.T) {
	tr := NewOnlineTracker()
	tr.Mark(5, "ip-a")
	tr.Mark(5, "ip-a")
	tr.Mark(5, "ip-b")

	tr.Unmark(5, "ip-a") // refcount drops to 1, ip-a still listed
	if got := tr.Snapshot()[5]; len(got) != 2 {
		t.Errorf("after first Unmark, uid=5 ips = %v, want 2 entries", got)
	}

	tr.Unmark(5, "ip-a") // ip-a fully gone
	snap := tr.Snapshot()
	if got := snap[5]; len(got) != 1 || got[0] != "ip-b" {
		t.Errorf("after second Unmark, uid=5 ips = %v, want [ip-b]", got)
	}

	tr.Unmark(5, "ip-b")
	if tr.Len() != 0 {
		t.Errorf("Len after full unmark = %d, want 0", tr.Len())
	}
}

func TestOnlineTracker_InvalidInput(t *testing.T) {
	tr := NewOnlineTracker()
	tr.Mark(0, "ip")
	tr.Mark(1, "")
	tr.Unmark(0, "x")
	tr.Unmark(99, "missing")
	if tr.Len() != 0 {
		t.Errorf("Len = %d, want 0", tr.Len())
	}
}

func TestOnlineTracker_SnapshotIsIndependent(t *testing.T) {
	tr := NewOnlineTracker()
	tr.Mark(1, "ip-a")
	snap := tr.Snapshot()
	snap[1] = append(snap[1], "ip-injected")

	snap2 := tr.Snapshot()
	if len(snap2[1]) != 1 || snap2[1][0] != "ip-a" {
		t.Errorf("snapshot mutation leaked: %v", snap2[1])
	}
}

func TestOnlineTracker_Concurrent(t *testing.T) {
	tr := NewOnlineTracker()
	const workers = 16
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tr.Mark(id+1, "10.0.0.1")
			tr.Mark(id+1, "10.0.0.1")
			tr.Unmark(id+1, "10.0.0.1")
		}(w)
	}
	wg.Wait()
	if tr.Len() != workers {
		t.Errorf("Len = %d, want %d", tr.Len(), workers)
	}
}
