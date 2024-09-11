package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/kataras/jwt"
	"io"
)

/* Чего б я добавил: время жизни токенов.
 * Их можно легко добавить к мапам токенов и оставить валидацию в Get...Payload.
 * При фейле такого рода проверок, можно выдавать и мап, и ошибку
 * (например при /refresh ошибка по времени жизни Access будет игнорироваться). */

type Pair struct {
	Access  []byte
	Refresh []byte
}

func NewPair(secret []byte, accessPayload map[string]interface{}, refreshPayload map[string]interface{}) (*Pair, error) {
	var err error
	tokenPair := &Pair{}
	tokenPair.Access, err = generateAccessToken(secret, accessPayload)
	if err == nil {
		tokenPair.Refresh, err = generateRefreshToken(secret, refreshPayload, tokenPair.Access)
	}
	return tokenPair, err
}

func generateAccessToken(secret []byte, payload map[string]interface{}) (accessToken []byte, err error) {
	accessToken, err = jwt.Sign(jwt.HS512, secret, payload)
	return
}

/* Refresh токен: 12 байт nonce + json + 12 байт access токена
 * Часть access токена не зашифрована, но включена в валидацию GCM AES-256 */
func generateRefreshToken(secret []byte, payload map[string]interface{}, accessToken []byte) ([]byte, error) {
	if len(accessToken) < 12 {
		return nil, errors.New("access token is too short")
	}
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

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	encryptedToken := append(nonce, gcm.Seal(nil, nonce, payloadJson, accessToken[len(accessToken)-12:])...)
	refreshToken := make([]byte, base64.RawStdEncoding.EncodedLen(len(encryptedToken)))
	base64.RawStdEncoding.Encode(refreshToken, encryptedToken)
	return refreshToken, nil
}

func (pair *Pair) RefreshTokenPayload(secret []byte) (payload map[string]interface{}, err error) {
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

	nonceSize := gcm.NonceSize()
	if len(encryptedToken) < nonceSize || len(pair.Access) < 12 {
		return nil, errors.New("one or all of the tokens are too short")
	}
	nonce, encryptedData := encryptedToken[:nonceSize], encryptedToken[nonceSize:]
	payloadJson, err := gcm.Open(nil, nonce, encryptedData, pair.Access[len(pair.Access)-12:])
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
