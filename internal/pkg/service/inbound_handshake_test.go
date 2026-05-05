// inbound_handshake_test.go pins the post-fix invariant that the TLS
// handshake on accepted sockets must be bounded by a deadline so a
// silent slow-loris client cannot tie up server goroutines indefinitely.
//
// We exercise serveConn by handing it one half of a net.Pipe whose other
// half never sends a single byte. With the handshake deadline in place,
// serveConn must close the raw conn within ~tlsHandshakeTimeout and
// return; without the fix, it blocks until the test deadline.
package service

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"
)

func TestServeConn_HandshakeDeadlineClosesSilentClient(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()

	// Empty TLS config; server will block waiting for ClientHello.
	tlsCfg := &tls.Config{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &Builder{ctx: ctx}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		b.serveConn(serverSide, tlsCfg, nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(tlsHandshakeTimeout + 2*time.Second):
		t.Fatal("serveConn did not enforce TLS handshake deadline; slow-loris bypass")
	}

	// After bail-out the raw conn must be closed (read returns immediately).
	_ = clientSide.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := clientSide.Read(make([]byte, 1)); err == nil {
		t.Error("raw conn should be closed after handshake deadline")
	}
	wg.Wait()
}
