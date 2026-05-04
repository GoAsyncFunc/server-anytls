// router.go converts a v2board route rule list into a typed Router
// suitable for per-connection lookups. Only the action subset that does
// not depend on a multi-outbound manager is honoured; unsupported actions
// log a warning at compile time and are silently bypassed at decision
// time. See docs/IMPLEMENTATION.zh-CN.md for the full mapping table.
package router

import (
	"net"
	"strconv"
	"strings"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	log "github.com/sirupsen/logrus"
)

// ActionKind enumerates the routing decisions the handler can act on.
type ActionKind int

const (
	// ActionAllow lets the handler dial the destination directly.
	ActionAllow ActionKind = iota
	// ActionBlock forces the handler to close the stream.
	ActionBlock
)

// Action is the lookup result returned by Decide.
type Action struct {
	Kind   ActionKind
	Reason string
}

// allowAction is shared as the default verdict for non-matching streams.
var allowAction = Action{Kind: ActionAllow}

type rule struct {
	domains  []string     // exact host matches (case-insensitive)
	suffixes []string     // domain suffix matches (".example.com")
	cidrs    []*net.IPNet // IP CIDRs
	ports    []int        // exact destination ports
}

// Router holds the compiled deny rules.
type Router struct {
	block rule
}

// Compile turns the panel route list into a Router. Unsupported action
// kinds emit a one-shot warning but never fail the build.
func Compile(routes []api.Route) (*Router, error) {
	r := &Router{}
	for _, rt := range routes {
		matches := rt.Matches()
		switch rt.Action {
		case api.RouteActionBlock:
			compileBlockMatches(&r.block, matches)
		case api.RouteActionBlockIP:
			compileBlockIP(&r.block, matches)
		case api.RouteActionBlockPort:
			compileBlockPort(&r.block, matches)
		case api.RouteActionProtocol,
			api.RouteActionDNS,
			api.RouteActionRoute,
			api.RouteActionRouteIP,
			api.RouteActionDefaultOut:
			log.Warnf("router: action %q is not implemented in server-anytls; rule ignored", rt.Action)
		default:
			log.Warnf("router: unknown action %q ignored", rt.Action)
		}
	}
	return r, nil
}

func compileBlockMatches(out *rule, matches []string) {
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		// "protocol:" prefixed matches are protocol-sniff rules — not
		// implemented here. Skip silently; uniproxy already separates
		// these in NormalizeRouteMatch but we double-guard.
		if strings.HasPrefix(m, "protocol:") {
			continue
		}
		// Treat "regexp:" prefix as plain suffix match (drop "regexp:")
		// because we don't run a regex engine on hot path.
		m = strings.TrimPrefix(m, "regexp:")
		if ip := net.ParseIP(m); ip != nil {
			if ip.To4() != nil {
				if _, n, err := net.ParseCIDR(m + "/32"); err == nil {
					out.cidrs = append(out.cidrs, n)
					continue
				}
			} else {
				if _, n, err := net.ParseCIDR(m + "/128"); err == nil {
					out.cidrs = append(out.cidrs, n)
					continue
				}
			}
		}
		if _, n, err := net.ParseCIDR(m); err == nil {
			out.cidrs = append(out.cidrs, n)
			continue
		}
		if strings.HasPrefix(m, ".") {
			out.suffixes = append(out.suffixes, strings.ToLower(m))
			continue
		}
		out.domains = append(out.domains, strings.ToLower(m))
	}
}

func compileBlockIP(out *rule, matches []string) {
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if !strings.Contains(m, "/") {
			if ip := net.ParseIP(m); ip != nil {
				if ip.To4() != nil {
					m += "/32"
				} else {
					m += "/128"
				}
			}
		}
		if _, n, err := net.ParseCIDR(m); err == nil {
			out.cidrs = append(out.cidrs, n)
		}
	}
}

func compileBlockPort(out *rule, matches []string) {
	for _, m := range matches {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if p, err := strconv.Atoi(m); err == nil && p > 0 && p < 65536 {
			out.ports = append(out.ports, p)
		}
	}
}

// Decide picks an action for the destination. host may be an IP literal
// or a domain; port == 0 disables port-rule matching.
func (r *Router) Decide(host string, port int) Action {
	if r == nil {
		return allowAction
	}

	host = strings.ToLower(strings.TrimSpace(host))
	for _, p := range r.block.ports {
		if p == port {
			return Action{Kind: ActionBlock, Reason: "block_port"}
		}
	}
	for _, d := range r.block.domains {
		if d == host {
			return Action{Kind: ActionBlock, Reason: "block:domain"}
		}
	}
	for _, s := range r.block.suffixes {
		if strings.HasSuffix(host, s) {
			return Action{Kind: ActionBlock, Reason: "block:suffix"}
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, n := range r.block.cidrs {
			if n.Contains(ip) {
				return Action{Kind: ActionBlock, Reason: "block_ip"}
			}
		}
	}
	return allowAction
}
