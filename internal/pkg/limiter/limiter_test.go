package limiter

import (
	"testing"
)

func TestSetAndBucket(t *testing.T) {
	Reset()
	Set(1, 10)
	if b := Bucket(1); b == nil {
		t.Fatal("Bucket(1) = nil after Set with mbps=10")
	}
}

func TestSetZeroOrNegativeRemovesBucket(t *testing.T) {
	Reset()
	Set(2, 5)
	if b := Bucket(2); b == nil {
		t.Fatal("precondition: bucket should exist")
	}
	Set(2, 0)
	if b := Bucket(2); b != nil {
		t.Errorf("Bucket(2) after Set(0) = %v, want nil", b)
	}

	Set(2, 5)
	Set(2, -1)
	if b := Bucket(2); b != nil {
		t.Errorf("Bucket(2) after Set(-1) = %v, want nil", b)
	}
}

func TestSetUnchangedKeepsBucketReference(t *testing.T) {
	Reset()
	Set(3, 7)
	first := Bucket(3)
	Set(3, 7)
	second := Bucket(3)
	if first != second {
		t.Errorf("expected stable bucket pointer when mbps unchanged")
	}
}

func TestSetUpdateReplacesBucket(t *testing.T) {
	Reset()
	Set(4, 5)
	first := Bucket(4)
	Set(4, 50)
	second := Bucket(4)
	if first == second {
		t.Errorf("expected new bucket when mbps changes")
	}
}

func TestRemove(t *testing.T) {
	Reset()
	Set(5, 1)
	Remove(5)
	if b := Bucket(5); b != nil {
		t.Errorf("Bucket(5) after Remove = %v, want nil", b)
	}
	Remove(5) // idempotent
}

func TestInvalidUIDsAreIgnored(t *testing.T) {
	Reset()
	Set(0, 100)
	Set(-3, 100)
	if Bucket(0) != nil || Bucket(-3) != nil {
		t.Errorf("non-positive uid produced a bucket")
	}
	Remove(0)
	Remove(-1)
}

func TestBucketRateBytesPerSec(t *testing.T) {
	Reset()
	Set(7, 1) // 1 Mbps = 125_000 bytes/sec
	b := Bucket(7)
	if b == nil {
		t.Fatal("missing bucket")
	}
	const wantBPS = int64(125_000)
	if got := b.Capacity(); got != wantBPS {
		t.Errorf("Capacity = %d, want %d", got, wantBPS)
	}
}
