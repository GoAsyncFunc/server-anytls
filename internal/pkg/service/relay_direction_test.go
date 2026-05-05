// relay_direction_test.go: pins relay() byte accounting to actual copy
// direction (tx = client → upstream, rx = upstream → client) and asserts
// non-EOF transport errors propagate to the caller.
package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// bufConn is a deterministic net.Conn substitute used to test relay's
// directional accounting without the timing surface of real sockets.
// Read drains a fixed payload then returns io.EOF; Write captures bytes
// for assertions; Close marks the conn closed and short-circuits reads.
type bufConn struct {
	mu     sync.Mutex
	read   *bytes.Reader
	write  *bytes.Buffer
	closed bool
}

func newBufConn(payload []byte) *bufConn {
	return &bufConn{
		read:  bytes.NewReader(payload),
		write: &bytes.Buffer{},
	}
}

func (c *bufConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, io.EOF
	}
	n, err := c.read.Read(p)
	if errors.Is(err, io.EOF) {
		return n, io.EOF
	}
	return n, err
}

func (c *bufConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	return c.write.Write(p)
}

func (c *bufConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *bufConn) Written() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.write.Bytes()...)
}

func (c *bufConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *bufConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *bufConn) SetDeadline(time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(time.Time) error { return nil }

func TestRelay_DirectionalAccounting(t *testing.T) {
	clientPayload := []byte("CLIENT-TO-UPSTREAM-1234567890")
	upstreamPayload := []byte("UPSTREAM-TO-CLIENT")

	client := newBufConn(clientPayload)
	upstream := newBufConn(upstreamPayload)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tx, rx, err := relay(ctx, client, upstream, nil)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if tx != uint64(len(clientPayload)) {
		t.Errorf("tx = %d, want %d (client→upstream)", tx, len(clientPayload))
	}
	if rx != uint64(len(upstreamPayload)) {
		t.Errorf("rx = %d, want %d (upstream→client)", rx, len(upstreamPayload))
	}
	// Bytes that travelled tx must end up on upstream's write buffer; rx
	// bytes must end up on client's write buffer.
	if got := upstream.Written(); !bytes.Equal(got, clientPayload) {
		t.Errorf("upstream received %q, want %q", got, clientPayload)
	}
	if got := client.Written(); !bytes.Equal(got, upstreamPayload) {
		t.Errorf("client received %q, want %q", got, upstreamPayload)
	}
}

func TestRelay_PropagatesNonEOFError(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer closeTestConn(t, clientA)
	defer closeTestConn(t, clientB)

	upstream := &errReadConn{err: errors.New("upstream read kaboom")}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = clientB.Close()
	}()

	_, _, err := relay(ctx, clientA, upstream, nil)
	if err == nil {
		t.Fatal("relay should surface non-EOF transport errors")
	}
}

// errReadConn is a net.Conn whose Read always fails with a configured error.
type errReadConn struct {
	err error
}

func (e *errReadConn) Read([]byte) (int, error)         { return 0, e.err }
func (e *errReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (e *errReadConn) Close() error                     { return nil }
func (e *errReadConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (e *errReadConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (e *errReadConn) SetDeadline(time.Time) error      { return nil }
func (e *errReadConn) SetReadDeadline(time.Time) error  { return nil }
func (e *errReadConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }
