// Package router compiles v2board route rules into an in-memory matcher
// and provides the private-network detector that --allow-private-outbound
// gates against.
//
// private.go: IP family classification used by both Decide() (for route
// matching against block_ip) and the handler (for the private outbound
// guard rail).
package router

import (
	"context"
	"fmt"
	"net"
	"time"
)

// resolveTimeout caps the per-call DNS budget when ResolveSafe takes the
// FQDN branch. Long enough to absorb a round-trip to a slow recursive
// resolver, short enough that handlers don't pile up.
const resolveTimeout = 5 * time.Second

// resolveLookup is package-mutable so tests can substitute a deterministic
// resolver. It returns the list of addresses bound to host, in resolver
// order.
var resolveLookup = func(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// privateV4 lists the CIDR blocks that the default deny path treats as
// private or otherwise reserved when --allow-private-outbound is false.
var privateV4 = []*net.IPNet{
	mustCIDR("0.0.0.0/8"),          // any-source / unspecified
	mustCIDR("10.0.0.0/8"),         // RFC1918
	mustCIDR("100.64.0.0/10"),      // CGNAT
	mustCIDR("127.0.0.0/8"),        // loopback
	mustCIDR("169.254.0.0/16"),     // link-local
	mustCIDR("172.16.0.0/12"),      // RFC1918
	mustCIDR("192.0.0.0/24"),       // IETF protocol assignments
	mustCIDR("192.0.2.0/24"),       // TEST-NET-1
	mustCIDR("192.168.0.0/16"),     // RFC1918
	mustCIDR("198.18.0.0/15"),      // benchmarking
	mustCIDR("198.51.100.0/24"),    // TEST-NET-2
	mustCIDR("203.0.113.0/24"),     // TEST-NET-3
	mustCIDR("224.0.0.0/4"),        // multicast
	mustCIDR("240.0.0.0/4"),        // reserved
	mustCIDR("255.255.255.255/32"), // broadcast
}

var privateV6 = []*net.IPNet{
	mustCIDR("::/128"),    // unspecified
	mustCIDR("::1/128"),   // loopback
	mustCIDR("fc00::/7"),  // unique-local
	mustCIDR("fe80::/10"), // link-local
	mustCIDR("ff00::/8"),  // multicast
	mustCIDR("100::/64"),  // discard prefix
}

// IsPrivate reports whether ip falls into a reserved or private network.
// nil input returns true (we refuse to dial nothing).
func IsPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range privateV4 {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range privateV6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsPrivateHost resolves a host string and returns true when at least one
// resolved address is private. Resolution failures classify the host as
// private (fail-closed) so the dialer never bypasses the guard rail
// because of a flaky DNS reply.
func IsPrivateHost(host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return IsPrivate(ip)
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return true
	}
	for _, a := range addrs {
		if IsPrivate(a) {
			return true
		}
	}
	return false
}

// ResolveSafe resolves host once and returns a single concrete IP that has
// passed the private-network filter. Callers must dial this exact IP, not
// the original hostname, to defeat DNS rebinding (TOCTOU between the
// guard check and the eventual connect).
//
// IP literals are validated in place. FQDN inputs are resolved with the
// supplied context bounded by resolveTimeout; if any resolved address is
// private the call fails (fail-closed against split-horizon rebind).
//
// Returns an error mentioning host on every refusal so logs stay
// diagnosable.
func ResolveSafe(ctx context.Context, host string) (net.IP, error) {
	if host == "" {
		return nil, fmt.Errorf("ResolveSafe: empty host")
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsPrivate(ip) {
			return nil, fmt.Errorf("ResolveSafe: %s is in a private/reserved range", host)
		}
		return ip, nil
	}

	rctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()

	addrs, err := resolveLookup(rctx, host)
	if err != nil {
		return nil, fmt.Errorf("ResolveSafe: lookup %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("ResolveSafe: %s resolved to no addresses", host)
	}
	for _, a := range addrs {
		if IsPrivate(a) {
			return nil, fmt.Errorf("ResolveSafe: %s resolves to private address %s", host, a)
		}
	}
	return addrs[0], nil
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("router: bad CIDR literal: " + s)
	}
	return n
}
