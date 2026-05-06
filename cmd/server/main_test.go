package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/GoAsyncFunc/server-anytls/internal/app/server"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

func newTestApp() *cli.App {
	return BuildApp(
		&server.Config{},
		&api.Config{},
		&service.Config{},
		&service.CertConfig{},
	)
}

func preserveLogState(t *testing.T) {
	t.Helper()
	formatter := log.StandardLogger().Formatter
	level := log.GetLevel()
	reportCaller := log.StandardLogger().ReportCaller
	t.Cleanup(func() {
		log.SetFormatter(formatter)
		log.SetLevel(level)
		log.SetReportCaller(reportCaller)
	})
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
		"fui":                    "fetch_users_interval",
		"rti":                    "report_traffics_interval",
		"hbi":                    "heartbeat_interval",
		"cni":                    "check_node_interval",
		"allow_private_outbound": "allow-private-outbound",
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

func TestBuildApp_NoAppLevelRequiredFlags(t *testing.T) {
	app := newTestApp()
	for _, f := range app.Flags {
		req, ok := f.(cli.RequiredFlag)
		if !ok {
			continue
		}
		if req.IsRequired() {
			t.Errorf("flag %q should validate in Action, not via app-level Required", f.Names()[0])
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

func TestBuildApp_ExpectedPrimaryFlagsExist(t *testing.T) {
	app := newTestApp()
	want := map[string]bool{
		"api":                      true,
		"token":                    true,
		"cert_file":                true,
		"key_file":                 true,
		"node":                     true,
		"fetch_users_interval":     true,
		"report_traffics_interval": true,
		"heartbeat_interval":       true,
		"check_node_interval":      true,
		"log_mode":                 true,
		"allow-private-outbound":   true,
	}
	got := make(map[string]bool, len(app.Flags))
	for _, f := range app.Flags {
		got[f.Names()[0]] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("missing primary flag %q", name)
		}
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	writerClosed := false
	defer func() {
		os.Stdout = old
		if !writerClosed {
			_ = w.Close()
		}
		_ = r.Close()
	}()

	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	writerClosed = true

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return buf.String()
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

func TestVersionCommandUsesCanonicalLine(t *testing.T) {
	app := newTestApp()
	ctx := cli.NewContext(app, flag.NewFlagSet("test", flag.ContinueOnError), nil)

	var versionCmd *cli.Command
	for _, cmd := range app.Commands {
		if cmd.Name == "version" {
			versionCmd = cmd
			break
		}
	}
	if versionCmd == nil {
		t.Fatal("missing version command")
	}
	got := captureStdout(t, func() {
		if err := versionCmd.Action(ctx); err != nil {
			t.Fatalf("version command: %v", err)
		}
	})

	want := versionLine(Name, Version) + "\n"
	if got != want {
		t.Fatalf("version output=%q want %q", got, want)
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

func TestBuildApp_BeforeConfiguresSupportedLogModes(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		wantLevel log.Level
	}{
		{"debug", server.LogLevelDebug, log.DebugLevel},
		{"info", server.LogLevelInfo, log.InfoLevel},
		{"error", server.LogLevelError, log.ErrorLevel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preserveLogState(t)
			cfg := &server.Config{LogLevel: tc.mode}
			app := BuildApp(cfg, &api.Config{}, &service.Config{}, &service.CertConfig{})
			ctx := cli.NewContext(app, flag.NewFlagSet("test", flag.ContinueOnError), nil)
			if err := app.Before(ctx); err != nil {
				t.Fatalf("Before(%q): %v", tc.mode, err)
			}
			if got := log.GetLevel(); got != tc.wantLevel {
				t.Errorf("log level=%v want %v", got, tc.wantLevel)
			}
		})
	}
}

func TestBuildApp_BeforeRejectsUnsupportedLogMode(t *testing.T) {
	preserveLogState(t)
	cfg := &server.Config{LogLevel: "trace"}
	app := BuildApp(cfg, &api.Config{}, &service.Config{}, &service.CertConfig{})
	ctx := cli.NewContext(app, flag.NewFlagSet("test", flag.ContinueOnError), nil)
	if err := app.Before(ctx); err == nil {
		t.Fatal("Before should reject unsupported log mode")
	}
}

func TestValidateRequiredConfigRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		cfg  api.Config
	}{
		{"missing api", api.Config{Key: "token", NodeID: 1}},
		{"missing token", api.Config{APIHost: "https://panel.example", NodeID: 1}},
		{"missing node", api.Config{APIHost: "https://panel.example", Key: "token"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateRequiredConfig(&tc.cfg); err == nil {
				t.Fatal("validateRequiredConfig should reject incomplete config")
			}
		})
	}
}

func TestValidateRequiredConfigAcceptsCompleteConfig(t *testing.T) {
	cfg := &api.Config{APIHost: "https://panel.example", Key: "token", NodeID: 1}
	if err := validateRequiredConfig(cfg); err != nil {
		t.Fatalf("validateRequiredConfig: %v", err)
	}
}
