package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// TimeFunc 可以提供获取当前时间的函数，也可以使用自定义的时间函数进行覆盖
var TimeFunc = time.Now

// Token 表示一个JWT token
type Token struct {
	Raw       string
	Method    SigningMethod
	Header    map[string]interface{}
	Claims    Claims
	Signature string
	Valid     bool
}

// New 创建一个新的Token
func New(method SigningMethod) *Token {
	return NewWithClaims(method, MapClaims{})
}

// NewWithClaims 创建一个新的JWT token
func NewWithClaims(method SigningMethod, claims Claims) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Algorithm(),
		},
		Claims: claims,
		Method: method,
	}
}

// Generate 生成完整的JWT Token
func (t *Token) Generate(key interface{}) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.CanonicalizeString(); err != nil {
		return "", err
	}
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

// CanonicalizeString 计算JWT Token的待签名字符串
func (t *Token) CanonicalizeString() (string, error) {
	var err error
	parts := make([]string, 2)
	for i := range parts {
		var jsonValue []byte
		if i == 0 {
			if jsonValue, err = json.Marshal(t.Header); err != nil {
				return "", err
			}
		} else {
			if jsonValue, err = json.Marshal(t.Claims); err != nil {
				return "", err
			}
		}

		parts[i] = EncodeSegment(jsonValue)
	}
	return strings.Join(parts, "."), nil
}

// EncodeSegment 按照JWT的编码规则为数据编码
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// DecodeSegment 按照JWT编码规则将数据解码为原始数据
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
