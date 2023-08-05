package logger

import (
	"go.uber.org/zap"
)

var (
	log	*zap.SugaredLogger
)

func initLogger(verbose bool) {
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
	defer logger.Sync() // Flushes buffer, if any
	log = logger.Sugar()
}