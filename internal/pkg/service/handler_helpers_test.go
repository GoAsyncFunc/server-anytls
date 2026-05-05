package service

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/juju/ratelimit"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
)

func closeTestConn(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Logf("close test conn: %v", err)
	}
}

func TestUidFromContext(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want int
	}{
		{"empty ctx", context.Background(), 0},
		{"valid email", auth.ContextWithUser(context.Background(), "tag|42|uuid"), 42},
		{"empty user", auth.ContextWithUser(context.Background(), ""), 0},
		{"malformed user", auth.ContextWithUser(context.Background(), "garbage"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := uidFromContext(tc.ctx); got != tc.want {
				t.Errorf("uidFromContext = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSocksaddrIP(t *testing.T) {
	ipAddr := M.ParseSocksaddrHostPort("8.8.8.8", 443)
	if got := socksaddrIP(ipAddr); got != "8.8.8.8" {
		t.Errorf("ip socksaddr = %q, want 8.8.8.8", got)
	}

	fqdnAddr := M.ParseSocksaddrHostPort("example.com", 443)
	if got := socksaddrIP(fqdnAddr); got != "example.com" {
		t.Errorf("fqdn socksaddr = %q, want example.com", got)
	}

	if got := socksaddrIP(M.Socksaddr{}); got != "" {
		t.Errorf("zero socksaddr = %q, want empty", got)
	}
}

func TestDestinationHostPort(t *testing.T) {
	ipAddr := M.ParseSocksaddrHostPort("1.2.3.4", 8080)
	if h, p := destinationHostPort(ipAddr); h != "1.2.3.4" || p != 8080 {
		t.Errorf("ip destination = %s:%d, want 1.2.3.4:8080", h, p)
	}

	fqdnAddr := M.ParseSocksaddrHostPort("foo.com", 443)
	if h, p := destinationHostPort(fqdnAddr); h != "foo.com" || p != 443 {
		t.Errorf("fqdn destination = %s:%d, want foo.com:443", h, p)
	}
}

func TestRateWriter(t *testing.T) {
	buf := &writeCollector{}
	w := rateWriter{Writer: buf, b: nil}
	n, err := w.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Errorf("write w/ nil bucket: n=%d err=%v", n, err)
	}
	if string(buf.data) != "hello" {
		t.Errorf("buf=%q want hello", buf.data)
	}

	bucket := ratelimit.NewBucketWithQuantum(time.Second, 1_000_000, 1_000_000)
	buf2 := &writeCollector{}
	w2 := rateWriter{Writer: buf2, b: bucket}
	n2, err := w2.Write([]byte("world"))
	if err != nil || n2 != 5 {
		t.Errorf("write w/ bucket: n=%d err=%v", n2, err)
	}
	if string(buf2.data) != "world" {
		t.Errorf("buf=%q want world", buf2.data)
	}
}

type writeCollector struct{ data []byte }

func (w *writeCollector) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func TestCloseWithCause(t *testing.T) {
	c1, c2 := net.Pipe()
	defer closeTestConn(t, c2)

	called := 0
	closeWithCause(c1, func(error) { called++ }, errors.New("boom"))
	if called != 1 {
		t.Errorf("onClose called %d times, want 1", called)
	}

	_ = c1.SetReadDeadline(time.Now())
	if _, err := c1.Read(make([]byte, 1)); err == nil {
		t.Error("expected close to make c1 unreadable")
	}

	c3, c4 := net.Pipe()
	defer closeTestConn(t, c4)
	closeWithCause(c3, nil, nil) // nil onClose must be safe
}

func TestRelayHandlesContextCancel(t *testing.T) {
	c1, c2 := net.Pipe()
	defer closeTestConn(t, c1)
	defer closeTestConn(t, c2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before relay starts

	done := make(chan struct{})
	go func() {
		_, _, _ = relay(ctx, c1, c2, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not return after context cancellation")
	}
}

func TestHandlerError(t *testing.T) {
	if got := handlerError("x").Error(); got != "x" {
		t.Errorf("handlerError.Error = %q, want x", got)
	}
	if errBlockedByRoute.Error() == "" {
		t.Error("errBlockedByRoute should have message")
	}
}
