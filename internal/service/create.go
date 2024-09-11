package service

import (
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
)

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
