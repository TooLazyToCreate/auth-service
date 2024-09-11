package service

import (
	"database/sql"
	"errors"
	"github.com/TooLazyToCreate/auth-service/config"
	"net/http"
	"net/smtp"
	"strconv"

	"github.com/TooLazyToCreate/auth-service/internal/repository"
	"github.com/TooLazyToCreate/auth-service/internal/token"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
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
	}, map[string]interface{}{"ip": req.RemoteAddr})
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

	/* Записываем хеш refresh токена и guid пользователя в таблицу tokens */
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

func (service *AuthService) HandleCreate(w http.ResponseWriter, req *http.Request) {
	/* Парсим запрос */
	if err := req.ParseForm(); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		service.logger.Error("Bad request", zap.Error(err), zap.String("ip", req.RemoteAddr))
		return
	}

	/* Проверяем GUID на соответствие своему типу */
	userGUID := req.FormValue("guid")
	if _, err := uuid.Parse(userGUID); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		service.logger.Error("Bad request", zap.Error(err), zap.String("ip", req.RemoteAddr))
		return
	}

	/* Проверяем, существует ли пользователь с таким GUID */
	if _, err := service.userRepo.GetByGUID(userGUID); err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		service.logger.Error("User not found", zap.Error(err),
			zap.String("ip", req.RemoteAddr),
			zap.String("user_guid", userGUID))
		return
	}

	/* Создаём пару токенов */
	service.createTokens(userGUID, w, req)
}

func (service *AuthService) HandleRefresh(w http.ResponseWriter, req *http.Request) {
	/* Парсим пару токенов из JSON */
	pair, err := token.PairFromStream(req.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		service.logger.Error("Bad request", zap.Error(err), zap.String("ip", req.RemoteAddr))
		return
	}

	/* Получаем данные из refresh токена, заодно его проверяя */
	refreshTokenPayload, err := pair.RefreshTokenPayload(service.cfg.Secret)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		service.logger.Error("Bad request", zap.Error(err), zap.String("ip", req.RemoteAddr))
		return
	}

	/* Получаем данные из access токена, заодно его проверяя */
	accessTokenPayload, err := pair.AccessTokenPayload(service.cfg.Secret)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		service.logger.Error("Bad request", zap.Error(err), zap.String("ip", req.RemoteAddr))
		return
	}

	/* Сверяем Ip адреса в двух токенах */
	refreshIpAddress, rIpExists := refreshTokenPayload["ip"]
	accessIpAddress, aIpExists := accessTokenPayload["ip"]
	if !(rIpExists && aIpExists && accessIpAddress == refreshIpAddress) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		service.logger.Error("Token payload mismatch", zap.String("ip", req.RemoteAddr))
		return
	}

	/* Получаем GUID пользователя из access токена */
	var userGUID string
	if accessTokenPayload["guid"] != nil {
		userGUID = accessTokenPayload["guid"].(string)
	} else {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		service.logger.Error("Access token does not contain enough data", zap.Error(err),
			zap.String("ip", req.RemoteAddr),
			zap.String("access_token", string(pair.Access)))
		return
	}

	/* Получаем все хэши refresh-токенов, выданные на конкретного пользователя */
	hashes, err := service.tokenRepo.GetByGUID(userGUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			service.logger.Error("Refresh token is invalid", zap.Error(err), zap.String("ip", req.RemoteAddr))
		} else {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			service.logger.Error("SQL error", zap.Error(err))
		}
		return
	}
	/* Если в выдаче есть валидный хэш, удаляем его и выходим из цикла */
	for _, hash := range hashes {
		if err = bcrypt.CompareHashAndPassword([]byte(hash), pair.Refresh); err == nil {
			err := service.tokenRepo.DeleteByHash(hash)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				service.logger.Error("SQL error", zap.Error(err))
				return
			}
			break
		}
	}
	/* Этот if запускается только если bcrypt.CompareHashAndPassword вернул error для каждого из хэшей */
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		service.logger.Error("Refresh token hash mismatch", zap.Error(err), zap.String("ip", req.RemoteAddr))
		return
	}
	/* Если токены валидны и были выданы, но ip адреса не совпадают,
	 * пишем об этом пользователю. */
	if req.RemoteAddr != accessIpAddress {
		user, err := service.userRepo.GetByGUID(userGUID)
		if err != nil {
			service.logger.Error("Access and Refresh tokens have been compromised, but user not found...",
				zap.String("ip", req.RemoteAddr),
				zap.String("user_guid", userGUID))
		} else {
			service.logger.Error("Access and Refresh tokens have been compromised",
				zap.String("ip", req.RemoteAddr),
				zap.String("token_ip", accessIpAddress.(string)),
				zap.String("user_guid", userGUID))
			err = smtp.SendMail(service.cfg.Smtp.Host+":"+strconv.Itoa(service.cfg.Smtp.Port),
				*service.smtpAuth, service.cfg.Smtp.Email, []string{user.Email},
				[]byte("Кто-то пытался получить доступ к вашему аккаунту c IP адреса "+req.RemoteAddr+"!"))
			if err != nil {
				service.logger.Error("Could not send email to user", zap.Error(err),
					zap.String("email", user.Email))
			}
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	/* Генерируем новую пару токенов */
	service.createTokens(userGUID, w, req)
}
