package logger

import (
	"go.uber.org/zap"
)

type Logger struct {
	sugar *zap.SugaredLogger
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

func InitLogger(verbose bool) *Logger {
	var cfg zap.Config
	if verbose {
		cfg = zap.NewDevelopmentConfig() // More verbose logging
	} else {
		cfg = zap.NewProductionConfig() // Only INFO level and above
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(err)
	}

	return &Logger{sugar: logger.Sugar()}
}