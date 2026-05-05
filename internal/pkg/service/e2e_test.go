// e2e_test.go runs an end-to-end loop entirely in-process:
//   client → TLS → sing-anytls(handshake) → handler → echo upstream
//
// It exercises the actual transport stack (TLS handshake, sing-anytls
// session multiplexing, the handler's freedom dialer, traffic counters,
// and the online tracker) without requiring a v2board panel. Use the
// `e2e` build tag (-tags=e2e) to run; the default short test cycle skips
// it because it opens loopback sockets.
//
//go:build e2e

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	testUUID = "00000000-1111-2222-3333-444444444444"
	testUID  = 7
	testTag  = "anytls-in"
)

// generateLocalhostPEM produces a self-signed cert+key pair valid for
// 127.0.0.1 / localhost, written to certPath / keyPath.
func generateLocalhostPEM(t *testing.T, certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startEchoUpstream launches a TCP echo server on a random loopback port.
func startEchoUpstream(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// startTestInbound boots an AnyTLS inbound (TLS + sing-anytls) backed by
// a Builder so traffic / online counters get exercised. Returns the
// listener address, the Builder for assertions, and a cleanup func.
func startTestInbound(t *testing.T) (string, *Builder, func()) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	generateLocalhostPEM(t, certPath, keyPath)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	ctx, cancel := context.WithCancel(context.Background())
	b := &Builder{
		config:       &Config{Cert: &CertConfig{CertFile: certPath, KeyFile: keyPath}, AllowPrivateOutbound: true},
		nodeInfo:     &api.NodeInfo{AnyTls: &api.AnyTlsNode{CommonNode: api.CommonNode{ServerPort: 0}}},
		ctx:          ctx,
		cancel:       cancel,
		inboundTag:   testTag,
		trafficStats: NewTrafficStats(),
		online:       NewOnlineTracker(),
		userList:     []api.UserInfo{{Id: testUID, Uuid: testUUID}},
	}

	svc, err := anytls.NewService(anytls.ServiceConfig{
		PaddingScheme: padding.DefaultPaddingScheme,
		Users:         BuildUsers(testTag, b.userList),
		Handler:       &handler{b: b},
		Logger:        newSingLogger(),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	b.service = svc

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	b.listener = ln

	go b.acceptLoop(ln, tlsCfg, svc)

	cleanup := func() {
		cancel()
		_ = ln.Close()
	}
	return ln.Addr().String(), b, cleanup
}

func TestEndToEnd_AnyTLSEcho(t *testing.T) {
	echoAddr, stopEcho := startEchoUpstream(t)
	defer stopEcho()

	serverAddr, b, stopServer := startTestInbound(t)
	defer stopServer()

	clientCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	certPEM, err := os.ReadFile(b.config.Cert.CertFile)
	if err != nil {
		t.Fatalf("ReadFile cert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: failed to parse cert")
	}
	clientTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		ServerName: "localhost",
	}

	clientCfg := anytls.ClientConfig{
		Password: testUUID,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", serverAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, clientTLSConfig.Clone())
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		Logger: newSingLogger(),
	}
	client, err := anytls.NewClient(clientCtx, clientCfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	dstHost, dstPortStr, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	dst := M.ParseSocksaddrHostPortStr(dstHost, dstPortStr)

	stream, err := client.CreateProxy(clientCtx, dst)
	if err != nil {
		t.Fatalf("CreateProxy: %v", err)
	}
	defer stream.Close()

	payload := []byte("ping-anytls-12345")
	if _, err := stream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(payload))
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatalf("ReadFull: %v (got %q)", err, got)
	}
	if string(got) != string(payload) {
		t.Errorf("echo = %q, want %q", got, payload)
	}

	_ = stream.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b.trafficStats.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	stats := b.trafficStats.GetAndReset()
	if len(stats) == 0 {
		t.Fatal("traffic stats were not recorded")
	}
	if stats[testUID].Tx == 0 {
		t.Errorf("expected non-zero Tx, got %+v", stats[testUID])
	}
	if stats[testUID].Rx == 0 {
		t.Errorf("expected non-zero Rx, got %+v", stats[testUID])
	}

	for time.Now().Before(deadline) {
		if b.online.Len() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := b.online.Len(); got != 0 {
		t.Errorf("online users after stream close = %d, want 0", got)
	}
}
