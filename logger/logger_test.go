package logger

import (
	"bytes"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLogger(t *testing.T) {
	assert := assert.New(t)

	// Create buffer to capture logs
	var buf bytes.Buffer

	// 1. Initialize logger with buffer as output
	logger := InitLogger(true, zapcore.AddSync(&buf))
	assert.NotNil(logger, "Failed to initialize logger")

	// 2. Test logs capture
	logger.Debugw("Debug message", "key", "value")
	assert.Contains(buf.String(), "Debug message", "Expected log message not found")
	assert.Contains(buf.String(), "key", "value", "Expected key-value pair not found")

	// ... other tests ...

	// Clear buffer for next set of logs
	buf.Reset()

	// 4. Test logger with production config
	logger = InitLogger(false, zapcore.AddSync(&buf))

	log.SetOutput(&buf)
	buf.Reset()

	logger.Debugw("Debug message", "key", "value")
	assert.NotContains(buf.String(), "Debug message", "Debug message should not be logged in production mode")

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