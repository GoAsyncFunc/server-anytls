// handler.go is the sing-anytls ServiceConfig.Handler. After a successful
// AnyTLS handshake the service hands us each multiplexed stream; we apply
// route, device-limit, private-network, and rate-limit policies, then
// pump bytes between the client stream and a freshly dialed upstream conn.
//
// Byte counters land in TrafficStats; online IPs land in OnlineTracker.
package service

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/juju/ratelimit"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"

	"github.com/GoAsyncFunc/server-anytls/internal/pkg/devlimit"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/limiter"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/router"
)

// dialTimeout caps how long we wait when establishing an upstream
// connection. Long enough to absorb cold TLS handshakes, short enough to
// fail fast on dead destinations.
const dialTimeout = 10 * time.Second

// dialContext is package-mutable so tests can substitute a fake.
var dialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext

// handler implements N.TCPConnectionHandlerEx for the sing-anytls Service.
type handler struct {
	b *Builder
}

// NewConnectionEx is invoked by sing-anytls for every demultiplexed stream.
// The supplied conn is plaintext (TLS + AnyTLS already peeled).
func (h *handler) NewConnectionEx(ctx context.Context, conn net.Conn,
	source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {

	uid := uidFromContext(ctx)
	srcIP := socksaddrIP(source)

	host, port := destinationHostPort(destination)
	if act := h.b.routerSnapshot().Decide(host, port); act.Kind == router.ActionBlock {
		log.Debugf("anytls handler: block %s:%d (%s)", host, port, act.Reason)
		closeWithCause(conn, onClose, errBlockedByRoute)
		return
	}

	if !devlimit.Acquire(uid, srcIP) {
		log.Debugf("anytls handler: device limit reached for uid=%d", uid)
		closeWithCause(conn, onClose, errDeviceLimitExceeded)
		return
	}
	defer devlimit.Release(uid, srcIP)

	h.b.online.Mark(uid, srcIP)
	defer h.b.online.Unmark(uid, srcIP)

	if !h.b.config.AllowPrivateOutbound && router.IsPrivateHost(host) {
		log.Debugf("anytls handler: refusing private/loopback destination %s", host)
		closeWithCause(conn, onClose, errPrivateDestination)
		return
	}
	if !destination.IsValid() {
		closeWithCause(conn, onClose, errInvalidDestination)
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	upstream, err := dialContext(dialCtx, "tcp", destination.String())
	cancel()
	if err != nil {
		log.Debugf("anytls handler: dial %s failed: %v", destination, err)
		closeWithCause(conn, onClose, err)
		return
	}
	defer upstream.Close()

	bucket := limiter.Bucket(uid)
	tx, rx := relay(ctx, conn, upstream, bucket)
	h.b.trafficStats.LogTraffic(uid, tx, rx)

	closeWithCause(conn, onClose, nil)
}

// uidFromContext extracts the v2board uid that sing-anytls authenticated
// against; returns 0 when the user lookup yielded nothing usable.
func uidFromContext(ctx context.Context) int {
	name, _ := auth.UserFromContext[string](ctx)
	if name == "" {
		return 0
	}
	uid, err := ParseUIDFromEmail(name)
	if err != nil {
		log.Debugf("anytls handler: cannot parse uid from %q: %v", name, err)
		return 0
	}
	return uid
}

// socksaddrIP extracts the source IP literal from a sing M.Socksaddr.
func socksaddrIP(addr M.Socksaddr) string {
	if addr.IsIP() {
		return addr.Addr.String()
	}
	if addr.Fqdn != "" {
		return addr.Fqdn
	}
	return ""
}

// destinationHostPort splits sing's M.Socksaddr into (host, port). host
// is the raw IP literal or FQDN; port is 0 when missing.
func destinationHostPort(addr M.Socksaddr) (host string, port int) {
	port = int(addr.Port)
	if addr.IsIP() {
		return addr.Addr.String(), port
	}
	return addr.Fqdn, port
}

// routerSnapshot returns the currently active router; nil-safe.
func (b *Builder) routerSnapshot() *router.Router {
	b.mu.Lock()
	r := b.router
	b.mu.Unlock()
	return r
}

// relay copies bytes between the client stream and the upstream conn in
// both directions, returning total byte counts (tx = client → upstream,
// rx = upstream → client). bucket throttles both directions when non-nil.
func relay(ctx context.Context, client, upstream net.Conn, bucket *ratelimit.Bucket) (tx, rx uint64) {
	type result struct{ n int64 }
	done := make(chan result, 2)

	go func() {
		n, _ := io.Copy(rateWriter{Writer: upstream, b: bucket}, client)
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- result{n}
	}()
	go func() {
		n, _ := io.Copy(rateWriter{Writer: client, b: bucket}, upstream)
		if cw, ok := client.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- result{n}
	}()

	for i := 0; i < 2; i++ {
		select {
		case r := <-done:
			if i == 0 {
				tx = uint64(r.n)
			} else {
				rx = uint64(r.n)
			}
		case <-ctx.Done():
			return tx, rx
		}
	}
	return tx, rx
}

// rateWriter wraps an io.Writer so each Write blocks on a token bucket.
// Nil bucket disables limiting.
type rateWriter struct {
	io.Writer
	b *ratelimit.Bucket
}

func (w rateWriter) Write(p []byte) (int, error) {
	if w.b != nil && len(p) > 0 {
		w.b.Wait(int64(len(p)))
	}
	return w.Writer.Write(p)
}

// closeWriter is satisfied by *net.TCPConn and similar half-close-capable
// connections.
type closeWriter interface {
	CloseWrite() error
}

// closeWithCause closes the conn and forwards the cause to sing-anytls
// via onClose (if supplied).
func closeWithCause(conn net.Conn, onClose N.CloseHandlerFunc, cause error) {
	_ = conn.Close()
	if onClose != nil {
		onClose(cause)
	}
}

// Sentinel errors keep handler-side decisions distinguishable in logs.
type handlerError string

func (e handlerError) Error() string { return string(e) }

const (
	errInvalidDestination  = handlerError("invalid destination address")
	errPrivateDestination  = handlerError("private destination refused")
	errDeviceLimitExceeded = handlerError("device limit exceeded")
	errBlockedByRoute      = handlerError("blocked by route rule")
)
