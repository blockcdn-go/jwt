package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

// RSAPSSMethod 实现RSAPSS 签名方法
type RSAPSSMethod struct {
	*RSAMethod
	Options *rsa.PSSOptions
}

// RSAPSS methods
var (
	PS256 *RSAPSSMethod
	PS384 *RSAPSSMethod
	PS512 *RSAPSSMethod
)

func init() {
	PS256 = &RSAPSSMethod{
		&RSAMethod{Name: "PS256", Hash: crypto.SHA256},
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256},
	}
	RegisterSigningMethod(PS256.Algorithm(), PS256)

	PS384 = &RSAPSSMethod{
		&RSAMethod{Name: "PS384", Hash: crypto.SHA384},
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA384},
	}
	RegisterSigningMethod(PS384.Algorithm(), PS384)

	PS512 = &RSAPSSMethod{
		&RSAMethod{Name: "PS512", Hash: crypto.SHA512},
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA512},
	}
	RegisterSigningMethod(PS512.Algorithm(), PS512)
}

// Verify 实现签名验证方法
func (m *RSAPSSMethod) Verify(signingString, siguature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = DecodeSegment(siguature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	switch k := key.(type) {
	case *rsa.PublicKey:
		rsaKey = k
	default:
		return ErrInvalidKeyType
	}

	if !m.Hash.Available() {
		return ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	return rsa.VerifyPSS(rsaKey, m.Hash, hasher.Sum(nil), sig, m.Options)
}

// Sign 实现签名方法
func (m *RSAPSSMethod) Sign(signingString string, key interface{}) (string, error) {
	var rsaKey *rsa.PrivateKey

	switch k := key.(type) {
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return "", ErrInvalidKeyType
	}

	if !m.Hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	if sigBytes, err := rsa.SignPSS(rand.Reader, rsaKey, m.Hash, hasher.Sum(nil), m.Options); err == nil {
		return EncodeSegment(sigBytes), nil
	} else {
		return "", err
	}
}
