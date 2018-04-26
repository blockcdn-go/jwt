package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// RSAMethod 实现了RSA家族的签名方法
type RSAMethod struct {
	Name string
	Hash crypto.Hash
}

// RSA methods
var (
	RS256 *RSAMethod
	RS384 *RSAMethod
	RS512 *RSAMethod
)

func init() {
	RS256 = &RSAMethod{"RS256", crypto.SHA256}
	RegisterSigningMethod(RS256.Algorithm(), RS256)

	RS384 = &RSAMethod{"RS384", crypto.SHA384}
	RegisterSigningMethod(RS384.Algorithm(), RS384)

	RS512 = &RSAMethod{"RS512", crypto.SHA512}
	RegisterSigningMethod(RS512.Algorithm(), RS512)
}

// Algorithm 返回签名对象使用的算法名称
func (m *RSAMethod) Algorithm() string {
	return m.Name
}

// Verify 基于RSA算法验证签名
func (m *RSAMethod) Verify(signingString, signature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return ErrInvalidKeyType
	}

	if !m.Hash.Available() {
		return ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	return rsa.VerifyPKCS1v15(rsaKey, m.Hash, hasher.Sum(nil), sig)
}

// Sign 基于RSA算法对字符串进行签名
func (m *RSAMethod) Sign(signingString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PrivateKey); !ok {
		return "", ErrInvalidKeyType
	}

	if !m.Hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil)); err == nil {
		return EncodeSegment(sigBytes), nil
	} else {
		return "", err
	}
}
