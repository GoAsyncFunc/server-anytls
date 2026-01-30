package service

import (
	log "github.com/sirupsen/logrus"

	"github.com/sagernet/sing/common/logger"
)

type AnyTlsLogger struct{}

var _ logger.Logger = (*AnyTlsLogger)(nil)

func (l *AnyTlsLogger) Trace(args ...any) {
	log.Trace(args...)
}

func (l *AnyTlsLogger) Debug(args ...any) {
	log.Debug(args...)
}

func (l *AnyTlsLogger) Info(args ...any) {
	log.Info(args...)
}

func (l *AnyTlsLogger) Warn(args ...any) {
	log.Warn(args...)
}

func (l *AnyTlsLogger) Error(args ...any) {
	log.Error(args...)
}

// Fatal wrapper
func (l *AnyTlsLogger) Fatal(args ...any) {
	log.Fatal(args...)
}

func (l *AnyTlsLogger) Panic(args ...any) {
	log.Panic(args...)
}
