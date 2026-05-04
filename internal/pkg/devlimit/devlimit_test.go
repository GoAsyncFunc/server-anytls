package devlimit

import "testing"

func TestAcquireWithinQuota(t *testing.T) {
	Reset()
	SetQuota(1, 2)
	if !Acquire(1, "ip-a") {
		t.Fatal("first Acquire should succeed")
	}
	if !Acquire(1, "ip-b") {
		t.Fatal("second distinct ip within quota should succeed")
	}
	if got := ActiveIPs(1); got != 2 {
		t.Errorf("ActiveIPs = %d, want 2", got)
	}
}

func TestAcquireRejectsBeyondQuota(t *testing.T) {
	Reset()
	SetQuota(2, 1)
	if !Acquire(2, "ip-a") {
		t.Fatal("first Acquire should succeed")
	}
	if Acquire(2, "ip-b") {
		t.Error("second distinct ip beyond quota should be rejected")
	}
	if got := ActiveIPs(2); got != 1 {
		t.Errorf("ActiveIPs = %d, want 1", got)
	}
}

func TestAcquireSameIPCountsAsOne(t *testing.T) {
	Reset()
	SetQuota(3, 1)
	for i := 0; i < 5; i++ {
		if !Acquire(3, "ip-shared") {
			t.Errorf("repeat Acquire %d should not be rejected", i)
		}
	}
	if got := ActiveIPs(3); got != 1 {
		t.Errorf("ActiveIPs = %d, want 1", got)
	}
}

func TestReleaseRefcount(t *testing.T) {
	Reset()
	SetQuota(4, 1)
	Acquire(4, "ip")
	Acquire(4, "ip")
	Release(4, "ip")
	if got := ActiveIPs(4); got != 1 {
		t.Errorf("ActiveIPs after one Release = %d, want 1", got)
	}
	Release(4, "ip")
	if got := ActiveIPs(4); got != 0 {
		t.Errorf("ActiveIPs after final Release = %d, want 0", got)
	}
	Release(4, "ip") // no-op
}

func TestQuotaZeroMeansUnlimited(t *testing.T) {
	Reset()
	SetQuota(5, 0)
	for i := 0; i < 100; i++ {
		ip := string(rune('a' + i%26))
		if !Acquire(5, ip) {
			t.Errorf("Acquire %d rejected with quota=0", i)
		}
	}
}

func TestNoQuotaSetMeansUnlimited(t *testing.T) {
	Reset()
	if !Acquire(6, "ip-a") {
		t.Error("Acquire without prior SetQuota should succeed")
	}
	if !Acquire(6, "ip-b") {
		t.Error("second Acquire without quota should succeed")
	}
}

func TestRemoveUserClears(t *testing.T) {
	Reset()
	SetQuota(7, 1)
	Acquire(7, "ip")
	RemoveUser(7)
	if got := ActiveIPs(7); got != 0 {
		t.Errorf("ActiveIPs after RemoveUser = %d, want 0", got)
	}
	if !Acquire(7, "ip") {
		t.Error("Acquire after RemoveUser should rebuild tracker")
	}
}

func TestInvalidInputs(t *testing.T) {
	Reset()
	if !Acquire(0, "ip") {
		t.Error("uid=0 should be untracked-success")
	}
	if !Acquire(1, "") {
		t.Error("empty ip should be untracked-success")
	}
	Release(0, "ip")
	Release(1, "")
	SetQuota(0, 5)
	RemoveUser(0)
	if ActiveIPs(0) != 0 || ActiveIPs(-1) != 0 {
		t.Error("invalid uid should report 0 active")
	}
}
