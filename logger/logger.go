package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	sugar *zap.SugaredLogger
}

type LoggerInterface interface {
	Sync()
	Infow(msg string, keysAndValues ...interface{})
	Errorf(template string, args ...interface{})
	Printf(template string, args ...interface{})
	Debugw(msg string, keysAndValues ...interface{})
	Debugf(template string, args ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Fatalw(msg string, keysAndValues ...interface{})
	Fatalf(template string, args ...interface{})
}

func (l *Logger) Sync() {
	_ = l.sugar.Sync()  // This could also return error if you want to handle it
}

func (l *Logger) Infow(msg string, keysAndValues ...interface{}) {
	l.sugar.Infow(msg, keysAndValues...)
}

func (l *Logger) Errorf(template string, args ...interface{}) {
	l.sugar.Errorf(template, args...)
}

func (l *Logger) Printf(template string, args ...interface{}) {
	l.sugar.Infof(template, args...)
}

func (l *Logger) Debugw(msg string, keysAndValues ...interface{}) {
	l.sugar.Debugw(msg, keysAndValues...)
}

func (l *Logger) Debugf(template string, args ...interface{}) {
	l.sugar.Debugf(template, args...)
}

func (l *Logger) Warnw(msg string, keysAndValues ...interface{}) {
	l.sugar.Warnw(msg, keysAndValues...)
}

func (l *Logger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.sugar.Fatalw(msg, keysAndValues...)
}

func (l *Logger) Fatalf(template string, args ...interface{}) {
	l.sugar.Fatalf(template, args...)
}

func InitLogger(verbose bool, writers ...zapcore.WriteSyncer) *Logger {
    var cfg zap.Config
    if verbose {
        cfg = zap.NewDevelopmentConfig() // More verbose logging
    } else {
        cfg = zap.NewProductionConfig() // Only INFO level and above
    }

    if len(writers) > 0 {
        core := zapcore.NewCore(
            zapcore.NewConsoleEncoder(cfg.EncoderConfig),  // Assuming you want console output for tests
            writers[0],
            cfg.Level,
        )
        logger := zap.New(core)
        return &Logger{sugar: logger.Sugar()}
    }

    logger, err := cfg.Build()
    if err != nil {
        panic(err)
    }

    return &Logger{sugar: logger.Sugar()}
}
