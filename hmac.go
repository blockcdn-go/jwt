package jwt

import (
	"crypto"
	"crypto/hmac"
)

// HMACMethod 实现了HMAC-SHA家族哈希函数
// 该哈希函数将用于对JWT Token进行签名
type HMACMethod struct {
	Name string
	Hash crypto.Hash
}

// 指定了SHA哈希家族函数的实例
var (
	HS256Method *HMACMethod
	HS384Method *HMACMethod
	HS512Method *HMACMethod
)

func init() {
	HS256Method = &HMACMethod{"HS256", crypto.SHA256}
	RegisterSigningMethod(HS256Method.Algorithm(), HS256Method)

	HS384Method = &HMACMethod{"HS384", crypto.SHA384}
	RegisterSigningMethod(HS384Method.Algorithm(), HS384Method)

	HS512Method = &HMACMethod{"HS512", crypto.SHA512}
	RegisterSigningMethod(HS512Method.Algorithm(), HS512Method)
}

// Algorithm 返回签名对象使用的算法名称
func (m *HMACMethod) Algorithm() string {
	return m.Name
}

// Sign 实现签名方法
func (m *HMACMethod) Sign(canonicalString string, key interface{}) (string, error) {
	if keyBytes, ok := key.([]byte); ok {
		if !m.Hash.Available() {
			return "", ErrHashUnavailable
		}

		hasher := hmac.New(m.Hash.New, keyBytes)
		hasher.Write([]byte(canonicalString))

		return EncodeSegment(hasher.Sum(nil)), nil
	}

	return "", ErrInvalidKeyType
}

// Verify 实现签名验证方法
func (m *HMACMethod) Verify(canonicalString string, signature string, key interface{}) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return ErrInvalidKeyType
	}

	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}

	if !m.Hash.Available() {
		return ErrSignatureInvalid
	}

	hasher := hmac.New(m.Hash.New, keyBytes)
	hasher.Write([]byte(canonicalString))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return ErrSignatureInvalid
	}

	return nil
}
