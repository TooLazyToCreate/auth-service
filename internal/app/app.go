package app

import (
	"database/sql"
	"errors"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/TooLazyToCreate/auth-service/config"
	"github.com/TooLazyToCreate/auth-service/internal/repository"
	"github.com/TooLazyToCreate/auth-service/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

func Run(logger *zap.Logger, cfg *config.Config) error {
	db, err := sql.Open("postgres", cfg.DatabaseDsn)
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	} else {
		logger.Info("Connected to database")
	}
	defer func() {
		err := db.Close()
		if err != nil {
			logger.Error("Connection to database was closed with error", zap.Error(err))
		}
	}()

	userRepo := repository.NewUserRepository(logger, db)
	tokenRepo := repository.NewTokenRepository(logger, db)

	/* Запускаем на фоне горутину с очисткой базы токенов раз в 5 секунд*/
	tokenClearTicker := time.NewTicker(time.Duration(cfg.Lifetime.ExpiredToken * int64(time.Second)))
	go func() {
		for {
			<-tokenClearTicker.C
			err := tokenRepo.DeleteExpired(time.Unix(time.Now().Unix()-cfg.Lifetime.RefreshToken, 0))
			if !(err == nil || errors.Is(err, sql.ErrNoRows)) {
				logger.Error("Failed to delete expired tokens", zap.Error(err))
			} else {
				logger.Debug("Expired tokens have been deleted")
			}
		}
	}()

	smtpAuth := smtp.PlainAuth("", cfg.Smtp.Login, cfg.Smtp.Password, cfg.Smtp.Host)
	authService := service.NewAuthService(logger, cfg, &smtpAuth, userRepo, tokenRepo)

	router := chi.NewRouter()

	// Это нагромождение выдаёт в RemoteAddr ip-адрес до переадресаций без порта
	router.Use(middleware.RealIP)
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			port := strings.Index(r.RemoteAddr, ":")
			if port != -1 {
				r.RemoteAddr = r.RemoteAddr[:port]
			}
			next.ServeHTTP(w, r)
		})
	})

	/* Устанавливаем свой логгер запросов в дебаг режиме */
	if cfg.Env == "DEV" {
		router.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logger.Debug("Request to "+r.RequestURI, zap.String("ip", r.RemoteAddr))
				next.ServeHTTP(w, r)
			})
		})
	}

	router.Post("/user/tokens/create", authService.HandleCreate)
	router.Post("/user/tokens/refresh", authService.HandleRefresh)

	serverAddress := cfg.Host + ":" + strconv.Itoa(cfg.Port)

	logger.Info("Will serve on " + serverAddress)
	return http.ListenAndServe(serverAddress, router)
}
