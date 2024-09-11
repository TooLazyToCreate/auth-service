package token

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

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

/* Пришлось сделать небольшой костыль,
 * который позволил бы нормально кодировать и декодировать пару байтовых токенов.
 * (хотя наверное можно как-то обойтись *json.RawMessage в основной структуре) */
type jsonPair struct {
	Access  string `json:"access_token,omitempty"`
	Refresh string `json:"refresh_token,omitempty"`
}

func PairFromStream(r io.Reader) (*Pair, error) {
	temp := jsonPair{}
	err := json.NewDecoder(r).Decode(&temp)
	return &Pair{
		Access:  []byte(temp.Access),
		Refresh: []byte(temp.Refresh),
	}, err
}

func (pair *Pair) ToJson() (result []byte, err error) {
	result, err = json.MarshalIndent(&jsonPair{
		Access:  string(pair.Access),
		Refresh: string(pair.Refresh),
	}, "", "  ")
	return
}
