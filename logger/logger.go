package logger

import (
	"go.uber.org/zap"
)

// var (
// 	log	*zap.SugaredLogger
// )

type Logger struct {
	sugar *zap.SugaredLogger
}

func (l *Logger) Sync() {
	_ = l.sugar.Sync()  // This could also return error if you want to handle it
}

func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.sugar.Infow(msg, keysAndValues...)
}

func (l *Logger) Debugw(msg string, keysAndValues ...interface{}) {
	l.sugar.Debugw(msg, keysAndValues...)
}

func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	l.sugar.Fatalw(msg, keysAndValues...)
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
	// defer logger.Sync() // Flushes buffer, if any
	// log = logger.Sugar()

	return &Logger{sugar: logger.Sugar()}
}