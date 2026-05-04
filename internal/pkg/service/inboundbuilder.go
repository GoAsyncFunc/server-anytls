// inboundbuilder.go opens (or replaces) the AnyTLS listener: it loads
// the cert pair, computes the padding scheme, instantiates sing-anytls,
// then runs the accept loop. The listener can be re-opened safely from
// checkNodeConfigMonitor when the panel changes ServerPort, ServerName,
// PaddingScheme, routes, or the cert files mutate on disk.
package service

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	M "github.com/sagernet/sing/common/metadata"
	log "github.com/sirupsen/logrus"

	"github.com/GoAsyncFunc/server-anytls/internal/pkg/router"
)

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
func (b *Builder) acceptLoop(ln net.Listener, tlsCfg *tls.Config, svc *anytls.Service) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			if b.ctx.Err() != nil {
				return
			}
			log.Debugf("acceptLoop exiting: %v", err)
			return
		}
		go b.serveConn(raw, tlsCfg, svc)
	}
}

// serveConn runs the TLS handshake then hands the plaintext stream to
// the sing-anytls service.
func (b *Builder) serveConn(raw net.Conn, tlsCfg *tls.Config, svc *anytls.Service) {
	tlsConn := tls.Server(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(b.ctx); err != nil {
		_ = raw.Close()
		log.Debugf("TLS handshake from %s failed: %v", raw.RemoteAddr(), err)
		return
	}
	src := M.SocksaddrFromNet(raw.RemoteAddr())
	if err := svc.NewConnection(b.ctx, tlsConn, src, nil); err != nil && err != io.EOF {
		log.Debugf("anytls service.NewConnection from %s: %v", raw.RemoteAddr(), err)
	}
}
