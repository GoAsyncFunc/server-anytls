// private_test.go covers the SSRF / DNS-rebinding hardening on top of
// the basic IsPrivate / IsPrivateHost coverage that lives in router_test.go.
package router

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestResolveSafe_PublicIPLiteralPassesThrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ip, err := ResolveSafe(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("ResolveSafe public literal: %v", err)
	}
	if !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("ResolveSafe returned %v, want 8.8.8.8", ip)
	}
}

func TestResolveSafe_PrivateLiteralRejected(t *testing.T) {
	ctx := context.Background()
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "fe80::1"} {
		ip, err := ResolveSafe(ctx, host)
		if err == nil {
			t.Errorf("ResolveSafe(%q) returned ip=%v err=nil; want error", host, ip)
		}
	}
}

func TestResolveSafe_EmptyHostFailsClosed(t *testing.T) {
	if _, err := ResolveSafe(context.Background(), ""); err == nil {
		t.Error("empty host must fail closed")
	}
}

func TestResolveSafe_IPv4MappedV6IsTreatedAsV4Private(t *testing.T) {
	// ::ffff:127.0.0.1 is an IPv4-mapped IPv6 form of 127.0.0.1; an
	// attacker could try to slip past a v4-only check by using this.
	if _, err := ResolveSafe(context.Background(), "::ffff:127.0.0.1"); err == nil {
		t.Error("ipv4-mapped private literal must be refused")
	}
}

func TestResolveSafe_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// "invalid.invalid" is reserved by RFC 6761 for tests; resolver lookup
	// must respect the cancelled context and return error.
	if _, err := ResolveSafe(ctx, "invalid.invalid"); err == nil {
		t.Error("cancelled context must cause ResolveSafe to fail closed")
	}
}

func TestResolveSafe_FQDNRebindRefused(t *testing.T) {
	// Inject a fake resolver that returns one public + one private IP;
	// ResolveSafe must reject because at least one private slipped in.
	prev := resolveLookup
	defer func() { resolveLookup = prev }()
	resolveLookup = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}, nil
	}
	if _, err := ResolveSafe(context.Background(), "mixed.example"); err == nil {
		t.Error("a host resolving to any private ip must be refused (rebind defense)")
	}
}

func TestResolveSafe_FQDNAllPublicReturnsFirst(t *testing.T) {
	prev := resolveLookup
	defer func() { resolveLookup = prev }()
	resolveLookup = func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("8.8.4.4")}, nil
	}
	ip, err := ResolveSafe(context.Background(), "fast.example")
	if err != nil {
		t.Fatalf("ResolveSafe public-only host: %v", err)
	}
	if !ip.Equal(net.ParseIP("1.1.1.1")) {
		t.Errorf("ResolveSafe returned %v, want 1.1.1.1 (first resolved IP)", ip)
	}
}

func TestResolveSafe_LookupErrorFailsClosed(t *testing.T) {
	prev := resolveLookup
	defer func() { resolveLookup = prev }()
	resolveLookup = func(_ context.Context, _ string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "synthetic", Name: "broken.example"}
	}
	if _, err := ResolveSafe(context.Background(), "broken.example"); err == nil {
		t.Error("resolver error must propagate as fail-closed")
	}
}

func TestResolveSafe_ErrorMessageMentionsHost(t *testing.T) {
	_, err := ResolveSafe(context.Background(), "10.0.0.55")
	if err == nil {
		t.Fatal("expected error for private IP")
	}
	if !strings.Contains(err.Error(), "10.0.0.55") {
		t.Errorf("error %q should mention host literal for diagnosability", err)
	}
}
