package main

import (
	"github.com/TooLazyToCreate/auth-service/config"
	"github.com/joho/godotenv"
	"log"
	"os"

	"github.com/TooLazyToCreate/auth-service/internal/app"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

func main() {
	var cfg *config.Config
	if workingDir, err := os.Getwd(); err != nil {
		log.Fatal("os.Getwd() failed with error - " + err.Error())
	} else {
		/* Раскомментировать при надобности, хотя это могла бы делать система сборки */
		if err := godotenv.Load(workingDir + "/go.env"); err != nil {
			log.Fatal("Error loading .env file; Error - " + err.Error())
		}
		//config.WriteTemplate(workingDir + "/config.json")
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

	// TODO глянуть, какие ошибки появляются при обычном закрытии сервера без ошибок в логике
	if err = app.Run(logger, cfg); err != nil {
		logger.Fatal("Server have been stopped with error - " + err.Error())
	} else {
		logger.Info("Server have been stopped.")
	}
}
