package app

import (
	"database/sql"
	"github.com/TooLazyToCreate/auth-service/config"
	"github.com/TooLazyToCreate/auth-service/internal/repository"
	"github.com/TooLazyToCreate/auth-service/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
)

func Run(logger *zap.Logger, cfg *config.Config) error {
	db, err := sql.Open("postgres", cfg.DatabaseUrl)
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	} else {
		logger.Info("Connected to database")
	}
	defer db.Close()

	userRepo := repository.NewUserRepository(logger, db)
	tokenRepo := repository.NewTokenRepository(logger, db)

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
