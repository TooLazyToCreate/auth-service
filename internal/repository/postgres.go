package repository

import (
	"database/sql"
	"github.com/TooLazyToCreate/auth-service/internal/model"
	"go.uber.org/zap"
	"time"
)

type tokenRepo struct {
	db     *sql.DB
	logger *zap.Logger
}

func NewTokenRepository(logger *zap.Logger, db *sql.DB) TokenRepository {
	return &tokenRepo{
		db:     db,
		logger: logger,
	}
}

func (r *tokenRepo) Create(hash string, userGUID string) error {
	_, err := r.db.Exec(`INSERT INTO tokens (hash, user_guid) VALUES ($1, $2)`, hash, userGUID)
	return err
}

func (r *tokenRepo) GetByGUID(userGUID string) ([]model.Token, error) {
	result := make([]model.Token, 0, 10)
	rows, err := r.db.Query(`SELECT * FROM tokens WHERE user_guid::text = $1;`, userGUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for i := 0; rows.Next(); i++ {
		temp := model.Token{}
		if err := rows.Scan(&temp.UserGUID, &temp.Hash, &temp.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, temp)
	}
	return result, nil
}

func (r *tokenRepo) DeleteByHash(hash string) error {
	_, err := r.db.Query(`DELETE FROM tokens WHERE hash = $1;`, hash)
	return err
}

func (r *tokenRepo) DeleteExpired(minCreatedAt time.Time) error {
	_, err := r.db.Query(`DELETE FROM tokens WHERE created_at < $1;`, minCreatedAt)
	return err
}

type userRepo struct {
	db     *sql.DB
	logger *zap.Logger
}

func NewUserRepository(logger *zap.Logger, db *sql.DB) UserRepository {
	return &userRepo{
		db:     db,
		logger: logger,
	}
}

func (r *userRepo) GetByGUID(guid string) (*model.User, error) {
	user := &model.User{}
	query := `SELECT * FROM users WHERE guid::text = $1`
	return user, r.db.QueryRow(query, guid).Scan(&user.GUID, &user.FirstName, &user.LastName, &user.Email)
}
