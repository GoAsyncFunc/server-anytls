// inboundbuilder.go opens (or replaces) the AnyTLS listener: it loads
// the cert pair, computes the padding scheme, instantiates sing-anytls,
// then runs the accept loop. The listener can be re-opened safely from
// checkNodeConfigMonitor when the panel changes ServerPort, ServerName,
// PaddingScheme, routes, or the cert files mutate on disk.
package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	M "github.com/sagernet/sing/common/metadata"
	log "github.com/sirupsen/logrus"

	"github.com/GoAsyncFunc/server-anytls/internal/pkg/router"
)

// tlsHandshakeTimeout caps how long an accepted socket may take to
// complete the TLS handshake before we drop it. Without this bound,
// silent slow-loris clients can hold goroutines indefinitely because
// HandshakeContext only respects the parent (long-lived) ctx.
const tlsHandshakeTimeout = 10 * time.Second

// anytlsHandshakeTimeout extends the deadline window to cover the AnyTLS
// framing handshake that runs after TLS completes. sing-anytls sets its
// own per-frame timing once the session is up; this only bounds the
// silent gap between TLS finished and the first AnyTLS frame.
const anytlsHandshakeTimeout = 30 * time.Second

// maxConcurrentHandshakes caps the number of accepted sockets that may
// be inside the TLS+AnyTLS handshake at the same time. Beyond this we
// drop newly accepted connections before allocating a goroutine, so a
// flood of half-open clients cannot exhaust process resources.
const maxConcurrentHandshakes = 1024

// contextForHandshake returns a child context bounded by deadline. parent
// may be nil (typical only in unit tests that exercise serveConn without
// a fully constructed Builder); in that case Background() is used.
func contextForHandshake(parent context.Context, deadline time.Time) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithDeadline(parent, deadline)
}

// startInbound builds (or rebuilds) the TLS listener, sing-anytls service,
// and route table from the current b.nodeInfo / b.config.
func (b *Builder) startInbound() error {
	b.mu.Lock()
	nodeInfo := b.nodeInfo
	cfg := b.config
	users := append([]api.UserInfo(nil), b.userList...)
	b.mu.Unlock()

	if nodeInfo == nil || nodeInfo.AnyTls == nil {
		return fmt.Errorf("node info missing AnyTLS config")
	}
	if cfg == nil || cfg.Cert == nil {
		return fmt.Errorf("missing cert config")
	}

	cert, err := tls.LoadX509KeyPair(cfg.Cert.CertFile, cfg.Cert.KeyFile)
	if err != nil {
		return fmt.Errorf("load cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if name := nodeInfo.AnyTls.ServerName; name != "" {
		tlsCfg.ServerName = name
	}

	scheme := padding.DefaultPaddingScheme
	if list := nodeInfo.AnyTls.PaddingScheme; len(list) > 0 {
		scheme = trimPaddingScheme(list)
	}

	rtr, err := router.Compile(nodeInfo.Routes)
	if err != nil {
		return fmt.Errorf("compile router: %w", err)
	}

	svc, err := anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: scheme,
		Users:         BuildUsers(b.inboundTag, users),
		Handler:       &handler{b: b},
		Logger:        newSingLogger(),
	})
	if err != nil {
		return fmt.Errorf("anytls.NewService: %w", err)
	}

	addr := formatListenAddr(nodeInfo.AnyTls.ServerPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Infof("AnyTLS listening on %s", addr)

	certBytes, keyBytes := readCertFiles(cfg.Cert.CertFile, cfg.Cert.KeyFile)

	b.mu.Lock()
	prev := b.listener
	b.listener = ln
	b.service = svc
	b.router = rtr
	b.tlsCert = certBytes
	b.tlsKey = keyBytes
	b.mu.Unlock()

	if prev != nil {
		_ = prev.Close()
	}

	go b.acceptLoop(ln, tlsCfg, svc)
	return nil
}

// acceptLoop runs the TCP→TLS→sing-anytls handshake chain for a single
// listener instance. It exits when ln.Accept fails (typically because
// startInbound replaced the listener or Close was called).
//
// A bounded semaphore caps concurrent handshakes so a slow-loris flood
// cannot inflate goroutine count without bound. When the cap is hit we
// close the freshly accepted socket immediately rather than block accept.
func (b *Builder) acceptLoop(ln net.Listener, tlsCfg *tls.Config, svc *anytls.Service) {
	sem := make(chan struct{}, maxConcurrentHandshakes)
	for {
		raw, err := ln.Accept()
		if err != nil {
			if b.ctx != nil && b.ctx.Err() != nil {
				return
			}
			log.Warnf("acceptLoop on %s exiting: %v", ln.Addr(), err)
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			log.Warnf("acceptLoop: handshake semaphore full (%d), dropping %s",
				maxConcurrentHandshakes, raw.RemoteAddr())
			_ = raw.Close()
			continue
		}
		go func(c net.Conn) {
			defer func() { <-sem }()
			b.serveConn(c, tlsCfg, svc)
		}(raw)
	}
}

// serveConn runs the TLS handshake then hands the plaintext stream to
// the sing-anytls service. The handshake is bounded by tlsHandshakeTimeout
// independently of any service-wide context so silent peers cannot stall.
func (b *Builder) serveConn(raw net.Conn, tlsCfg *tls.Config, svc *anytls.Service) {
	deadline := time.Now().Add(tlsHandshakeTimeout)
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		log.Warnf("serveConn: SetDeadline on %s failed: %v", raw.RemoteAddr(), err)
		return
	}

	tlsConn := tls.Server(raw, tlsCfg)
	handshakeCtx, cancel := contextForHandshake(b.ctx, deadline)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		log.Warnf("TLS handshake from %s failed: %v", raw.RemoteAddr(), err)
		return
	}

	// Extend deadline to bound the AnyTLS framing handshake. sing-anytls
	// sets its own per-frame timing on the underlying conn after the
	// session is established; the deadline therefore only fires if the
	// peer never sends a single AnyTLS frame.
	if err := raw.SetDeadline(time.Now().Add(anytlsHandshakeTimeout)); err != nil {
		_ = tlsConn.Close()
		log.Warnf("serveConn: extend deadline on %s failed: %v", raw.RemoteAddr(), err)
		return
	}

	if svc == nil {
		// Tests exercise the deadline path without a sing-anytls service.
		_ = tlsConn.Close()
		return
	}

	src := M.SocksaddrFromNet(raw.RemoteAddr())
	if err := svc.NewConnection(b.ctx, tlsConn, src, nil); err != nil && err != io.EOF {
		log.Warnf("anytls service.NewConnection from %s: %v", raw.RemoteAddr(), err)
	}
}
