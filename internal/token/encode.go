package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"

	"github.com/kataras/jwt"
)

type Pair struct {
	Access  []byte
	Refresh []byte
}

func NewPair(secret []byte, accessPayload, refreshPayload map[string]interface{}) (*Pair, error) {
	uniqueID, err := randomBytes(12)
	if err != nil {
		return nil, err
	}
	finalPayload := map[string]interface{}{
		"jti": uniqueID,
	}
	maps.Copy(finalPayload, accessPayload)
	tokenPair := &Pair{}
	tokenPair.Access, err = generateAccessToken(secret, finalPayload)
	if err != nil {
		return nil, err
	}
	if len(tokenPair.Access) < 12 {
		return nil, errors.New("token is too short")
	} else {
		tokenPair.Refresh, err = generateRefreshToken(secret, refreshPayload, tokenPair.Access[len(tokenPair.Access)-12:])
	}
	return tokenPair, err
}

func generateAccessToken(secret []byte, payload map[string]interface{}) (accessToken []byte, err error) {
	accessToken, err = jwt.Sign(jwt.HS512, secret, payload)
	return
}

func generateRefreshToken(secret []byte, payload map[string]interface{}, nonce []byte) ([]byte, error) {
	payloadJson, err := json.Marshal(&payload)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	encryptedToken := gcm.Seal(nil, nonce, payloadJson, nil)
	refreshToken := make([]byte, base64.RawStdEncoding.EncodedLen(len(encryptedToken)))
	base64.RawStdEncoding.Encode(refreshToken, encryptedToken)
	return refreshToken, nil
}

func randomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, bytes)
	return bytes, err
}
