package logger

import (
	"bytes"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const debugMessage = "Debug message"

type MockLogger struct {
	InfoLogs  []string
	DebugLogs []string
	ErrorLogs []string
	FatalLogs []string
	PrintLogs []string
	WarnLogs  []string
	SyncCalls int
}

func (l *MockLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.InfoLogs = append(l.InfoLogs, msg)
}

func (l *MockLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.DebugLogs = append(l.DebugLogs, msg)
}

func (l *MockLogger) Debugf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.DebugLogs = append(l.DebugLogs, formattedMsg)
}

func (l *MockLogger) Errorf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.ErrorLogs = append(l.ErrorLogs, formattedMsg)
}

func (l *MockLogger) Fatalf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.FatalLogs = append(l.FatalLogs, formattedMsg)
}

func (l *MockLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.FatalLogs = append(l.FatalLogs, msg)
}

func (l *MockLogger) Printf(msg string, args ...interface{}) {
	formattedMsg := fmt.Sprintf(msg, args...)
    l.PrintLogs = append(l.PrintLogs, formattedMsg)
}

func (l *MockLogger) Sync() {
	l.SyncCalls++
}

func (l *MockLogger) Warnw(msg string, keysAndValues ...interface{}) {
	// Capture logs if necessary
	l.WarnLogs = append(l.WarnLogs, msg)
}

func TestLogger(t *testing.T) {
	assert := assert.New(t)

	// Create buffer to capture logs
	var buf bytes.Buffer

	// 1. Initialize logger with buffer as output
	logger := InitLogger(true, zapcore.AddSync(&buf))
	assert.NotNil(logger, "Failed to initialize logger")

	// 2. Test logs capture
	logger.Debugw(debugMessage, "key", "value")
	assert.Contains(buf.String(), debugMessage, "Expected log message not found")
	assert.Contains(buf.String(), "key", "value", "Expected key-value pair not found")

	// ... other tests ...

	// Clear buffer for next set of logs
	buf.Reset()

	// 4. Test logger with production config
	logger = InitLogger(false, zapcore.AddSync(&buf))

	log.SetOutput(&buf)
	buf.Reset()

	logger.Debugw(debugMessage, "key", "value")
	assert.NotContains(buf.String(), debugMessage, "Debug message should not be logged in production mode")

	logger.Infow("Info message", "info_key", "info_value")
	assert.Contains(buf.String(), "Info message", "Expected log message not found in production mode")
}

func init() {
	// Override zap's global logger to write logs to standard logger
	zapCore := zapcore.NewCore(
		zapcore.NewConsoleEncoder(zapcore.EncoderConfig{}),
		zapcore.AddSync(log.Writer()),
		zapcore.DebugLevel,
	)
	zap.ReplaceGlobals(zap.New(zapCore))
}