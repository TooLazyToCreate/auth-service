package token

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/kataras/jwt"
)

func (pair *Pair) RefreshTokenPayload(secret []byte) (payload map[string]interface{}, err error) {
	if len(pair.Access) < 12 {
		return nil, errors.New("token is too short")
	}
	encryptedToken := make([]byte, base64.RawStdEncoding.DecodedLen(len(pair.Refresh)))
	_, err = base64.RawStdEncoding.Decode(encryptedToken, pair.Refresh)
	if err != nil {
		return
	}
	c, err := aes.NewCipher(secret)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return
	}
	payloadJson, err := gcm.Open(nil, pair.Access[len(pair.Access)-12:], encryptedToken, nil)
	if err != nil {
		return
	}
	err = json.Unmarshal(payloadJson, &payload)
	return
}

func (pair *Pair) AccessTokenPayload(secret []byte) (claims map[string]interface{}, err error) {
	verifiedToken, err := jwt.Verify(jwt.HS512, secret, []byte(pair.Access))
	if err == nil {
		err = verifiedToken.Claims(&claims)
	}
	return
}
