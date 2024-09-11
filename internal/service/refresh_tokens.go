package service

import (
	"database/sql"
	"errors"
	"github.com/TooLazyToCreate/auth-service/internal/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/smtp"
	"strconv"
	"time"
)

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

	/* Проверяем время жизни токена */
	refreshIat, ok := refreshTokenPayload["iat"].(float64)
	if !(ok && time.Now().Unix()-int64(refreshIat) < service.cfg.Lifetime.RefreshToken) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		service.logger.Error("Refresh token is expired", zap.String("ip", req.RemoteAddr))
		return
	}

	/* TODO добавить столбец времени выпуска в tokens,
	 * чтоб хоть как-то контролировать рост неиспользованных токенов. */

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
		service.logger.Error("Access token does not contain enough data",
			zap.String("ip", req.RemoteAddr),
			zap.String("access_token", string(pair.Access)))
		return
	}

	/* Получаем все хэши refresh-токенов, выданные на конкретного пользователя */
	tokenRows, err := service.tokenRepo.GetByGUID(userGUID)
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

	/* Эта ошибка покажется только в случае, если у пользователя в таблице лежат только токены с вышедшим сроком годности,
	 * и они совпадает по хэшу (не уверен, что такое возможно). В других случаях будет писаться сообщение от bcrypt`а. */
	err = errors.New("there are no valid tokens exists for user")
	/* Если в выдаче есть валидный хэш, удаляем его и выходим из цикла */
	for _, tokenRow := range tokenRows {
		if tokenRow.CreatedAt.Unix()+service.cfg.Lifetime.RefreshToken > time.Now().Unix() {
			if err = bcrypt.CompareHashAndPassword([]byte(tokenRow.Hash), pair.Refresh); err == nil {
				err = service.tokenRepo.DeleteByHash(tokenRow.Hash)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					service.logger.Error("SQL error", zap.Error(err))
					return
				}
				break
			}
		}
	}
	/* Этот if запускается только если bcrypt.CompareHashAndPassword вернул error для каждого из хэшей */
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		service.logger.Error("Refresh token is invalid", zap.Error(err), zap.String("ip", req.RemoteAddr))
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
