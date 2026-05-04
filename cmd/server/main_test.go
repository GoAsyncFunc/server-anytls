package main

import (
	"testing"

	cli "github.com/urfave/cli/v2"

	"github.com/GoAsyncFunc/server-anytls/internal/app/server"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

// newTestApp constructs a CLI app with fresh zero-valued destinations for tests.
func newTestApp() *cli.App {
	return BuildApp(
		&server.Config{},
		&api.Config{},
		&service.Config{},
		&service.CertConfig{},
	)
}

func TestBuildApp_NoFlagCollisions(t *testing.T) {
	app := newTestApp()
	seen := make(map[string]string)
	for _, f := range app.Flags {
		primary := f.Names()[0]
		for _, n := range f.Names() {
			if existing, ok := seen[n]; ok && existing != primary {
				t.Fatalf("flag identifier %q used by both %q and %q", n, existing, primary)
			}
			seen[n] = primary
		}
	}
}

func TestBuildApp_AliasesWired(t *testing.T) {
	app := newTestApp()
	want := map[string]string{
		"fui": "fetch_users_interval",
		"rti": "report_traffics_interval",
		"hbi": "heartbeat_interval",
	}
	flagsByName := map[string]cli.Flag{}
	for _, f := range app.Flags {
		flagsByName[f.Names()[0]] = f
	}
	for alias, primary := range want {
		f, ok := flagsByName[primary]
		if !ok {
			t.Fatalf("missing primary flag %q", primary)
		}
		found := false
		for _, n := range f.Names() {
			if n == alias {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("flag %q missing alias %q; have %v", primary, alias, f.Names())
		}
	}
}

func TestBuildApp_RequiredFlags(t *testing.T) {
	app := newTestApp()
	wantRequired := map[string]bool{
		"api":   true,
		"token": true,
		"node":  true,
	}
	for _, f := range app.Flags {
		name := f.Names()[0]
		req, ok := f.(cli.RequiredFlag)
		if !ok {
			continue
		}
		got := req.IsRequired()
		want, has := wantRequired[name]
		switch {
		case has && !got:
			t.Errorf("flag %q expected Required=true, got false", name)
		case !has && got:
			t.Errorf("flag %q unexpectedly Required=true", name)
		case has && want != got:
			t.Errorf("flag %q Required mismatch: want %v got %v", name, want, got)
		}
	}
}

func TestBuildApp_LogModeDefault(t *testing.T) {
	app := newTestApp()
	for _, f := range app.Flags {
		if f.Names()[0] != "log_mode" {
			continue
		}
		s, ok := f.(*cli.StringFlag)
		if !ok {
			t.Fatalf("log_mode wrong type: %T", f)
		}
		if s.Value != server.LogLevelError {
			t.Errorf("log_mode default = %q, want %q", s.Value, server.LogLevelError)
		}
		return
	}
	t.Fatal("log_mode flag not found")
}

func TestBuildApp_PrimaryFlagCount(t *testing.T) {
	app := newTestApp()
	got := len(app.Flags)
	const want = 9
	if got != want {
		names := make([]string, 0, got)
		for _, f := range app.Flags {
			names = append(names, f.Names()[0])
		}
		t.Errorf("flag count = %d, want %d (have: %v)", got, want, names)
	}
}

func TestBuildApp_VersionConstant(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
	app := newTestApp()
	if app.Version != Version {
		t.Errorf("app.Version = %q, want %q", app.Version, Version)
	}
}

func TestBuildApp_AppMetadata(t *testing.T) {
	app := newTestApp()
	if app.Name != Name {
		t.Errorf("app.Name = %q, want %q", app.Name, Name)
	}
	if app.Copyright != CopyRight {
		t.Errorf("app.Copyright = %q, want %q", app.Copyright, CopyRight)
	}
	if len(app.Commands) == 0 {
		t.Fatal("app has no commands; expected version subcommand")
	}
	hasVersion := false
	for _, cmd := range app.Commands {
		if cmd.Name == "version" {
			hasVersion = true
			break
		}
	}
	if !hasVersion {
		t.Error("missing 'version' subcommand")
	}
}
