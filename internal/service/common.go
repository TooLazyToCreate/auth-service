package service

import (
	"github.com/TooLazyToCreate/auth-service/config"
	"github.com/TooLazyToCreate/auth-service/internal/repository"
	"github.com/TooLazyToCreate/auth-service/internal/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/smtp"
	"time"
)

type AuthService struct {
	logger    *zap.Logger
	cfg       *config.Config
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	smtpAuth  *smtp.Auth
}

func NewAuthService(logger *zap.Logger, cfg *config.Config, smtpAuth *smtp.Auth, userRepo repository.UserRepository, tokenRepo repository.TokenRepository) *AuthService {
	return &AuthService{
		logger,
		cfg,
		userRepo,
		tokenRepo,
		smtpAuth,
	}
}

func (service *AuthService) createTokens(userGUID string, w http.ResponseWriter, req *http.Request) {
	/* В access токене содержится guid пользователя и ip-адрес;
	 * В refresh токене содержится только ip-адрес. */
	pair, err := token.NewPair(service.cfg.Secret, map[string]interface{}{
		"guid": userGUID,
		"ip":   req.RemoteAddr,
		"iat":  time.Now().Unix(),
	}, map[string]interface{}{"ip": req.RemoteAddr, "iat": time.Now().Unix()})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		service.logger.Error("Failed to generate token", zap.Error(err),
			zap.String("ip", req.RemoteAddr),
			zap.String("user_guid", userGUID))
		return
	}

	/* Генерируем bcrypt хэш refresh токена */
	refreshTokenHash, err := bcrypt.GenerateFromPassword(pair.Refresh, bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		service.logger.Error("Failed to generate bcrypt hash", zap.Error(err),
			zap.String("refresh_token", string(pair.Refresh)),
			zap.String("user_guid", userGUID))
		return
	}

	/* Записываем хэш refresh токена и guid пользователя в таблицу tokens */
	err = service.tokenRepo.Create(string(refreshTokenHash), userGUID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		service.logger.Error("Failed to write bcrypt hash to database",
			zap.Error(err), zap.String("ip", req.RemoteAddr),
			zap.String("user_guid", userGUID))
		return
	}

	/* Выдаём пару токенов в виде JSON */
	result, err := pair.ToJson()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		service.logger.Error("JSON failure", zap.Error(err))
		return
	}
	service.logger.Debug("New tokens were given")
	w.WriteHeader(http.StatusCreated)
	w.Write(result)
}
