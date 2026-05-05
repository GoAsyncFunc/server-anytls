// builder_rollback_test.go pins the post-fix invariant that a node-info
// reload that fails inside startInbound must NOT leave the Builder
// claiming the new config is active. Otherwise nodeChanged() compares
// future panel polls against the unfinished update and stops retrying.
//
// The fix introduces applyNodeInfoSafely(next, start), which swaps in
// next, attempts the supplied start hook, and reverts to the previous
// nodeInfo if the hook fails.
package service

import (
	"errors"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestApplyNodeInfoSafely_RollsBackOnFailure(t *testing.T) {
	prev := &api.NodeInfo{
		AnyTls: &api.AnyTlsNode{CommonNode: api.CommonNode{ServerPort: 443}},
	}
	next := &api.NodeInfo{
		AnyTls: &api.AnyTlsNode{CommonNode: api.CommonNode{ServerPort: 8443}},
	}
	b := &Builder{nodeInfo: prev, config: &Config{}}

	called := 0
	err := b.applyNodeInfoSafely(next, func() error {
		called++
		return errors.New("simulated startInbound failure")
	})
	if err == nil {
		t.Fatal("applyNodeInfoSafely should propagate start failure")
	}
	if called != 1 {
		t.Errorf("start hook invoked %d times, want 1", called)
	}
	if b.nodeInfo != prev {
		t.Errorf("nodeInfo was not rolled back; got %p want %p", b.nodeInfo, prev)
	}
}

func TestApplyNodeInfoSafely_CommitsOnSuccess(t *testing.T) {
	prev := &api.NodeInfo{
		AnyTls: &api.AnyTlsNode{CommonNode: api.CommonNode{ServerPort: 443}},
	}
	next := &api.NodeInfo{
		AnyTls: &api.AnyTlsNode{CommonNode: api.CommonNode{ServerPort: 9443}},
	}
	b := &Builder{nodeInfo: prev, config: &Config{}}

	err := b.applyNodeInfoSafely(next, func() error { return nil })
	if err != nil {
		t.Fatalf("applyNodeInfoSafely: %v", err)
	}
	if b.nodeInfo != next {
		t.Errorf("nodeInfo was not committed; got %p want %p", b.nodeInfo, next)
	}
}

func TestApplyNodeInfoSafely_NodeChangedSeesRollback(t *testing.T) {
	// After a rollback, a subsequent nodeChanged(next) call must STILL
	// return true so the next monitor tick retries the failing reload.
	prev := &api.NodeInfo{
		AnyTls: &api.AnyTlsNode{CommonNode: api.CommonNode{ServerPort: 443}},
	}
	next := &api.NodeInfo{
		AnyTls: &api.AnyTlsNode{CommonNode: api.CommonNode{ServerPort: 8443}},
	}
	b := &Builder{nodeInfo: prev, config: &Config{}}

	_ = b.applyNodeInfoSafely(next, func() error { return errors.New("boom") })
	if !b.nodeChanged(next) {
		t.Error("nodeChanged should still report change after a rolled-back update")
	}
}
