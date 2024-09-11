package token

import (
	"encoding/json"
	"io"
)

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
