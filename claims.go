package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// Claims 所有作为claim添加到JWT body中的项都必须实现该接口
// 可以用于检测token是否合法
type Claims interface {
	Valid() error
}

// StandardClaims 是包提供的标准claims对象，你也添加自定义claim
type StandardClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	ID        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

// Valid 方法用来验证标准claims是否合法，如果上面列出的某些claim未出现在token中
// 那么我们仍然认为该token是合法的
func (c StandardClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().UTC().Unix()

	if !c.VerifyExpiresAt(now, false) {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if !c.VerifyIssuedAt(now, false) {
		vErr.Inner = fmt.Errorf("token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !c.VerifyNotBefore(now, false) {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// VerifyAudience 用于验证(Audience) Claim的合法性
func (c *StandardClaims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// VerifyExpiresAt 用于验证(Expiration Time) Claim的合法性
func (c *StandardClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

// VerifyIssuedAt 用于验证(Issued At) Claim的合法性
func (c *StandardClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	return verifyIat(c.IssuedAt, cmp, req)
}

// VerifyIssuer 用于验证(Issuer) Claim的合法性
func (c *StandardClaims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// VerifyNotBefore 用于验证(Not Before) Claim的合法性
func (c *StandardClaims) VerifyNotBefore(cmp int64, req bool) bool {
	return verifyNbf(c.NotBefore, cmp, req)
}

func verifyAud(aud string, cmp string, required bool) bool {
	if aud == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)) != 0 {
		return true
	}
	return false
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	}

	return false
}

func verifyNbf(nbf int64, now int64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}
