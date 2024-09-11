package repository

import (
	"github.com/TooLazyToCreate/auth-service/internal/model"
	"time"
)

type UserRepository interface {
	GetByGUID(guid string) (*model.User, error)
}

/* Для токенов я бы предложил использовать Redis, потому что:
 * 1. Лучше подходит для хранения key:value пар;
 * 2. Можно использовать команду EXPIRE, чтобы токены сами удалялись. */
type TokenRepository interface {
	Create(hash string, userGUID string) error
	GetByGUID(userGUID string) ([]model.Token, error)
	DeleteByHash(hash string) error
	DeleteExpired(maxLifeTime time.Time) error
}
