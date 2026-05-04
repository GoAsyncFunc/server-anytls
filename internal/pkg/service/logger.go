// logger.go adapts logrus to the sing-anytls logger.ContextLogger
// interface so sing-anytls internals can emit through the same pipeline
// as the rest of the node. newSingLogger returns a fresh adapter.
package service

import (
	"context"

	"github.com/sagernet/sing/common/logger"
	log "github.com/sirupsen/logrus"
)

// AnyTlsLogger forwards every sing-anytls log call to the process-wide
// logrus logger. Context variants ignore the context because logrus does
// not carry request-scoped state in this project.
type AnyTlsLogger struct{}

// compile-time interface assertions
var (
	_ logger.Logger        = (*AnyTlsLogger)(nil)
	_ logger.ContextLogger = (*AnyTlsLogger)(nil)
)

// newSingLogger returns a ready-to-use adapter. Factory form keeps the
// zero-value type opaque to callers.
func newSingLogger() *AnyTlsLogger { return &AnyTlsLogger{} }

func (l *AnyTlsLogger) Trace(args ...any) { log.Trace(args...) }
func (l *AnyTlsLogger) Debug(args ...any) { log.Debug(args...) }
func (l *AnyTlsLogger) Info(args ...any)  { log.Info(args...) }
func (l *AnyTlsLogger) Warn(args ...any)  { log.Warn(args...) }
func (l *AnyTlsLogger) Error(args ...any) { log.Error(args...) }
func (l *AnyTlsLogger) Fatal(args ...any) { log.Fatal(args...) }
func (l *AnyTlsLogger) Panic(args ...any) { log.Panic(args...) }

func (l *AnyTlsLogger) TraceContext(_ context.Context, args ...any) { log.Trace(args...) }
func (l *AnyTlsLogger) DebugContext(_ context.Context, args ...any) { log.Debug(args...) }
func (l *AnyTlsLogger) InfoContext(_ context.Context, args ...any)  { log.Info(args...) }
func (l *AnyTlsLogger) WarnContext(_ context.Context, args ...any)  { log.Warn(args...) }
func (l *AnyTlsLogger) ErrorContext(_ context.Context, args ...any) { log.Error(args...) }
func (l *AnyTlsLogger) FatalContext(_ context.Context, args ...any) { log.Fatal(args...) }
func (l *AnyTlsLogger) PanicContext(_ context.Context, args ...any) { log.Panic(args...) }
