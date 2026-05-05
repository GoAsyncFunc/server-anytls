package service

import (
	"context"
	"errors"
	"net"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/GoAsyncFunc/server-anytls/internal/pkg/devlimit"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/router"
)

func newHandlerTestConn(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

func newHandlerTestSubject(t *testing.T, r *router.Router, allowPrivate bool) *handler {
	t.Helper()
	if r == nil {
		var err error
		r, err = router.Compile(nil)
		if err != nil {
			t.Fatalf("router.Compile: %v", err)
		}
	}
	return &handler{b: &Builder{
		config:       &Config{AllowPrivateOutbound: allowPrivate},
		trafficStats: NewTrafficStats(),
		online:       NewOnlineTracker(),
		router:       r,
	}}
}

func contextWithUID(uid int) context.Context {
	return auth.ContextWithUser(context.Background(), BuildUserEmail(defaultInboundTag, uid, "uuid"))
}

func TestHandlerNewConnectionEx_BlocksRouteBeforeDial(t *testing.T) {
	r, err := router.Compile([]api.Route{{Action: api.RouteActionBlock, Match: "blocked.example"}})
	if err != nil {
		t.Fatalf("router.Compile: %v", err)
	}
	h := newHandlerTestSubject(t, r, true)
	server, _ := newHandlerTestConn(t)

	prevDial := dialContext
	dialed := false
	dialContext = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}
	defer func() { dialContext = prevDial }()

	var cause error
	h.NewConnectionEx(
		contextWithUID(7),
		server,
		M.ParseSocksaddrHostPort("203.0.113.10", 12345),
		M.ParseSocksaddrHostPort("blocked.example", 443),
		func(err error) { cause = err },
	)

	if dialed {
		t.Fatal("blocked route should not dial upstream")
	}
	if !errors.Is(cause, errBlockedByRoute) {
		t.Fatalf("onClose cause=%v want errBlockedByRoute", cause)
	}
	if h.b.trafficStats.Len() != 0 {
		t.Errorf("blocked route should not record traffic")
	}
}

func TestHandlerNewConnectionEx_RejectsDeviceLimitBeforeDial(t *testing.T) {
	devlimit.Reset()
	defer devlimit.Reset()
	devlimit.SetQuota(7, 1)
	if !devlimit.Acquire(7, "203.0.113.1") {
		t.Fatal("test setup Acquire should succeed")
	}
	defer devlimit.Release(7, "203.0.113.1")

	h := newHandlerTestSubject(t, nil, true)
	server, _ := newHandlerTestConn(t)

	prevDial := dialContext
	dialed := false
	dialContext = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}
	defer func() { dialContext = prevDial }()

	var cause error
	h.NewConnectionEx(
		contextWithUID(7),
		server,
		M.ParseSocksaddrHostPort("203.0.113.2", 12345),
		M.ParseSocksaddrHostPort("8.8.8.8", 443),
		func(err error) { cause = err },
	)

	if dialed {
		t.Fatal("device-limit rejection should not dial upstream")
	}
	if !errors.Is(cause, errDeviceLimitExceeded) {
		t.Fatalf("onClose cause=%v want errDeviceLimitExceeded", cause)
	}
}

func TestHandlerNewConnectionEx_RejectsPrivateDestinationBeforeDial(t *testing.T) {
	h := newHandlerTestSubject(t, nil, false)
	server, _ := newHandlerTestConn(t)

	prevDial := dialContext
	dialed := false
	dialContext = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}
	defer func() { dialContext = prevDial }()

	var cause error
	h.NewConnectionEx(
		contextWithUID(7),
		server,
		M.ParseSocksaddrHostPort("203.0.113.10", 12345),
		M.ParseSocksaddrHostPort("127.0.0.1", 80),
		func(err error) { cause = err },
	)

	if dialed {
		t.Fatal("private destination should not dial upstream")
	}
	if !errors.Is(cause, errPrivateDestination) {
		t.Fatalf("onClose cause=%v want errPrivateDestination", cause)
	}
}

func TestHandlerNewConnectionEx_PropagatesDialFailure(t *testing.T) {
	h := newHandlerTestSubject(t, nil, true)
	server, _ := newHandlerTestConn(t)

	want := errors.New("dial refused")
	prevDial := dialContext
	dialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, want
	}
	defer func() { dialContext = prevDial }()

	var cause error
	h.NewConnectionEx(
		contextWithUID(7),
		server,
		M.ParseSocksaddrHostPort("203.0.113.10", 12345),
		M.ParseSocksaddrHostPort("8.8.8.8", 443),
		func(err error) { cause = err },
	)

	if !errors.Is(cause, want) {
		t.Fatalf("onClose cause=%v want dial error", cause)
	}
	if got := h.b.online.Len(); got != 0 {
		t.Errorf("online Len=%d want 0 after dial failure cleanup", got)
	}
}
