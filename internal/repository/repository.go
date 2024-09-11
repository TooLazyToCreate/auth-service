package repository

import (
	"github.com/TooLazyToCreate/auth-service/internal/model"
)

type UserRepository interface {
	GetByGUID(guid string) (*model.User, error)
}

/* Для токенов я бы предложил использовать Redis, потому что:
 * 1. Лучше подходит для хранения key:value пар;
 * 2. Можно использовать команду EXPIRE, чтобы токены сами удалялись. */
type TokenRepository interface {
	Create(hash string, userGUID string) error
	GetByGUID(userGUID string) ([]string, error)
	DeleteByHash(hash string) error
}
