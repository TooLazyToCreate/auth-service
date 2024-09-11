package main

import (
	"log"
	"os"

	"github.com/TooLazyToCreate/auth-service/config"
	"github.com/TooLazyToCreate/auth-service/internal/app"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func main() {
	var cfg *config.Config
	if workingDir, err := os.Getwd(); err != nil {
		log.Fatal("os.Getwd() failed with error - " + err.Error())
	} else {
		envMode := os.Getenv("GO_ENV")
		if envMode == "" {
			if err := godotenv.Load(workingDir + "/go.env"); err != nil {
				log.Fatal("go.env loading failed error - " + err.Error())
			}
		}
		cfg = config.MustLoad(workingDir + "/config.json")
	}

	zapConfig := zap.NewProductionConfig()
	if cfg.Env == "DEV" {
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		zapConfig.Development = true
	} else {
		zapConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
		zapConfig.Development = false
	}
	zapConfig.OutputPaths = []string{"stdout"}      //, "/var/log/" + "auth-service.log"}
	zapConfig.ErrorOutputPaths = []string{"stderr"} //, "/var/log/" + "auth-service.log"}
	logger, err := zapConfig.Build()
	if err != nil {
		log.Fatal("Failed to setup logger, error - " + err.Error())
	}

	// TODO глянуть, какие ошибки появляются при обычном закрытии сервера без ошибок в логике
	if err = app.Run(logger, cfg); err != nil {
		logger.Fatal("Server have been stopped with error - " + err.Error())
	} else {
		logger.Info("Server have been stopped.")
	}
}
