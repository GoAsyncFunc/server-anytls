package server

import (
	"testing"

	"github.com/GoAsyncFunc/server-anytls/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func TestNewReturnsServer(t *testing.T) {
	cfg := &Config{LogLevel: LogLevelInfo}
	apiCfg := &api.Config{APIHost: "http://example", Key: "k", NodeID: 1, NodeType: api.AnyTls}
	svcCfg := &service.Config{}

	srv, err := New(cfg, apiCfg, svcCfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv == nil {
		t.Fatal("New returned nil server")
	}
	if srv.config != cfg {
		t.Error("config not retained")
	}
	if srv.serviceConfig != svcCfg {
		t.Error("serviceConfig not retained")
	}
	if srv.logLevel != LogLevelInfo {
		t.Errorf("logLevel = %q, want %q", srv.logLevel, LogLevelInfo)
	}
}

func TestCloseBeforeStartIsSafe(t *testing.T) {
	srv, err := New(
		&Config{LogLevel: LogLevelError},
		&api.Config{APIHost: "http://example", Key: "k", NodeID: 1, NodeType: api.AnyTls},
		&service.Config{},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.Close() // must not panic with nil cancel / nil service
	srv.Close() // idempotent
}

func TestLogLevelConstants(t *testing.T) {
	cases := map[string]string{
		LogLevelDebug: "debug",
		LogLevelInfo:  "info",
		LogLevelError: "error",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("level constant = %q, want %q", got, want)
		}
	}
}
