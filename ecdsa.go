package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"
)

// errors
var (
	ErrECDSAVerification = errors.New("crypto/ecdsa: verification error")
)

// ECDSAMethod 实现基于ECDSA算法的签名
type ECDSAMethod struct {
	Name      string
	Hash      crypto.Hash
	KeySize   int
	CurveBits int
}

// ecdsa methods
var (
	ES256 *ECDSAMethod
	ES384 *ECDSAMethod
	ES512 *ECDSAMethod
)

func init() {
	ES256 = &ECDSAMethod{"ES256", crypto.SHA256, 32, 256}
	RegisterSigningMethod(ES256.Algorithm(), ES256)

	ES384 = &ECDSAMethod{"ES384", crypto.SHA384, 48, 384}
	RegisterSigningMethod(ES384.Algorithm(), ES384)

	ES512 = &ECDSAMethod{"ES512", crypto.SHA512, 66, 521}
	RegisterSigningMethod(ES512.Algorithm(), ES512)
}

// Algorithm 返回算法名称字符串
func (m *ECDSAMethod) Algorithm() string {
	return m.Name
}

// Verify 验证签名
func (m *ECDSAMethod) Verify(signingString, signature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = DecodeSegment(signature); err != nil {
		return err
	}

	var ecdsaKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		ecdsaKey = k
	default:
		return ErrInvalidKeyType
	}

	if len(sig) != 2*m.KeySize {
		return ErrECDSAVerification
	}

	r := big.NewInt(0).SetBytes(sig[:m.KeySize])
	s := big.NewInt(0).SetBytes(sig[m.KeySize:])

	if !m.Hash.Available() {
		return ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	if verifystatus := ecdsa.Verify(ecdsaKey, hasher.Sum(nil), r, s); verifystatus {
		return nil
	} else {
		return ErrECDSAVerification
	}
}

// Sign 计算签名
func (m *ECDSAMethod) Sign(signingString string, key interface{}) (string, error) {
	var ecdsaKey *ecdsa.PrivateKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		ecdsaKey = k
	default:
		return "", ErrInvalidKeyType
	}

	if !m.Hash.Available() {
		return "", ErrHashUnavailable
	}

	hasher := m.Hash.New()
	hasher.Write([]byte(signingString))

	if r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, hasher.Sum(nil)); err == nil {
		curvBites := ecdsaKey.Params().BitSize

		if m.CurveBits != curvBites {
			return "", ErrInvalidKey
		}

		keyBytes := curvBites / 8
		if curvBites%8 > 0 {
			keyBytes++
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		out := append(rBytesPadded, sBytesPadded...)

		return EncodeSegment(out), nil
	} else {
		return "", err
	}
}
