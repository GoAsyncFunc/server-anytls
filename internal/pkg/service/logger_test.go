package service

import (
	"bytes"
	"context"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestNewSingLoggerNotNil(t *testing.T) {
	if newSingLogger() == nil {
		t.Fatal("newSingLogger returned nil")
	}
}

// TestAnyTlsLoggerForwards drains every non-terminating method through a
// captured logrus instance and asserts each emits at least once.
// Fatal / Panic are skipped because their logrus implementations
// terminate the goroutine.
func TestAnyTlsLoggerForwards(t *testing.T) {
	prevOut := log.StandardLogger().Out
	prevLevel := log.StandardLogger().GetLevel()
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetLevel(prevLevel)
	})

	buf := &bytes.Buffer{}
	log.SetOutput(buf)
	log.SetLevel(log.TraceLevel)

	l := newSingLogger()
	ctx := context.Background()

	l.Trace("trace-msg")
	l.Debug("debug-msg")
	l.Info("info-msg")
	l.Warn("warn-msg")
	l.Error("error-msg")
	l.TraceContext(ctx, "trace-ctx-msg")
	l.DebugContext(ctx, "debug-ctx-msg")
	l.InfoContext(ctx, "info-ctx-msg")
	l.WarnContext(ctx, "warn-ctx-msg")
	l.ErrorContext(ctx, "error-ctx-msg")

	out := buf.String()
	for _, want := range []string{
		"trace-msg", "debug-msg", "info-msg", "warn-msg", "error-msg",
		"trace-ctx-msg", "debug-ctx-msg", "info-ctx-msg", "warn-ctx-msg", "error-ctx-msg",
	} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("expected log output to contain %q; got %q", want, out)
		}
	}
}
