package router

import (
	"net"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestIsPrivateV4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		{"224.0.0.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.114.1", false},
		{"172.32.0.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := IsPrivate(net.ParseIP(tc.ip))
			if got != tc.want {
				t.Errorf("IsPrivate(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestIsPrivateV6(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"::1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"ff00::1", true},
		{"::", true},
		{"2001:4860:4860::8888", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := IsPrivate(net.ParseIP(tc.ip))
			if got != tc.want {
				t.Errorf("IsPrivate(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestIsPrivateNil(t *testing.T) {
	if !IsPrivate(nil) {
		t.Error("nil IP must be considered private")
	}
}

func TestIsPrivateHostLiterals(t *testing.T) {
	if !IsPrivateHost("10.0.0.5") {
		t.Error("private literal misclassified")
	}
	if IsPrivateHost("8.8.8.8") {
		t.Error("public literal misclassified")
	}
	if !IsPrivateHost("") {
		t.Error("empty host should fail-closed")
	}
}

func TestRouterCompileEmpty(t *testing.T) {
	r, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := r.Decide("anything.com", 443); got.Kind != ActionAllow {
		t.Errorf("empty router should allow, got %+v", got)
	}
}

func TestRouterBlockDomain(t *testing.T) {
	routes := []api.Route{
		{Action: api.RouteActionBlock, Match: "evil.example,tracker.test"},
	}
	r, err := Compile(routes)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if r.Decide("evil.example", 443).Kind != ActionBlock {
		t.Error("evil.example should be blocked")
	}
	if r.Decide("Evil.Example", 443).Kind != ActionBlock {
		t.Error("case-insensitive match expected")
	}
	if r.Decide("good.com", 443).Kind != ActionAllow {
		t.Error("good.com should be allowed")
	}
}

func TestRouterBlockSuffix(t *testing.T) {
	routes := []api.Route{
		{Action: api.RouteActionBlock, Match: ".ads.example"},
	}
	r, _ := Compile(routes)
	if r.Decide("foo.ads.example", 443).Kind != ActionBlock {
		t.Error("suffix should match")
	}
	// Bare "ads.example" must NOT match suffix ".ads.example" because
	// HasSuffix requires the leading dot too.
	if r.Decide("ads.example", 443).Kind == ActionBlock {
		t.Error("bare ads.example unexpectedly matched .ads.example suffix")
	}
}

func TestRouterBlockIP(t *testing.T) {
	routes := []api.Route{
		{Action: api.RouteActionBlockIP, Match: "10.0.0.0/8"},
		{Action: api.RouteActionBlockIP, Match: "8.8.8.8"},
	}
	r, _ := Compile(routes)
	if r.Decide("10.1.2.3", 443).Kind != ActionBlock {
		t.Error("CIDR block missed")
	}
	if r.Decide("8.8.8.8", 443).Kind != ActionBlock {
		t.Error("single-IP block missed")
	}
	if r.Decide("9.9.9.9", 443).Kind != ActionAllow {
		t.Error("unrelated IP should be allowed")
	}
}

func TestRouterBlockPort(t *testing.T) {
	routes := []api.Route{
		{Action: api.RouteActionBlockPort, Match: "25,587"},
	}
	r, _ := Compile(routes)
	if r.Decide("any.com", 25).Kind != ActionBlock {
		t.Error("port 25 should be blocked")
	}
	if r.Decide("any.com", 443).Kind != ActionAllow {
		t.Error("port 443 should be allowed")
	}
}

func TestRouterUnsupportedActionsAreIgnored(t *testing.T) {
	routes := []api.Route{
		{Action: api.RouteActionDNS, Match: "main,dns://8.8.8.8"},
		{Action: api.RouteActionRoute, Match: "x.com"},
		{Action: api.RouteActionRouteIP, Match: "1.2.3.4"},
		{Action: api.RouteActionDefaultOut, Match: ""},
		{Action: api.RouteActionProtocol, Match: "protocol:bittorrent"},
	}
	r, err := Compile(routes)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if r.Decide("x.com", 443).Kind != ActionAllow {
		t.Error("unsupported actions must not produce a block")
	}
}

func TestRouterNilSafe(t *testing.T) {
	var r *Router
	if r.Decide("anything", 443).Kind != ActionAllow {
		t.Error("nil router must allow")
	}
}
