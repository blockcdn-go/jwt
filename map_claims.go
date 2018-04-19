package jwt

import (
	"encoding/json"
	"errors"
)

// MapClaims 是基于map[string]interface{}实现的Claims类型
// 如果你创建JWT时未指定Claims，那么它将作为默认的Claims类型
type MapClaims map[string]interface{}

// VerifyAudience 用于验证(Audience) Claim的合法性
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	v, ok := m["aud"]
	if !ok {
		return !req
	}
	aud, ok := v.(string)
	if !ok {
		return false
	}
	return verifyAud(aud, cmp, req)
}

// VerifyExpiresAt 用于验证(Expiration Time) Claim的合法性
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	switch exp := m["exp"].(type) {
	case float64:
		return verifyExp(int64(exp), cmp, req)
	case json.Number:
		v, _ := exp.Int64()
		return verifyExp(v, cmp, req)
	}

	return !req
}

// VerifyIssuedAt 用于验证(Issued At) Claim的合法性
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	switch iat := m["iat"].(type) {
	case float64:
		return verifyIat(int64(iat), cmp, req)
	case json.Number:
		v, _ := iat.Int64()
		return verifyIat(v, cmp, req)
	}
	return !req
}

// VerifyIssuer 用于验证(Issuer) Claim的合法性
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	v, ok := m["iss"]
	if !ok {
		return !req
	}

	iss, ok := v.(string)
	if !ok {
		return false
	}

	return verifyIss(iss, cmp, req)
}

// VerifyNotBefore 用于验证(Not Before) Claim的合法性
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	switch nbf := m["nbf"].(type) {
	case float64:
		return verifyNbf(int64(nbf), cmp, req)
	case json.Number:
		v, _ := nbf.Int64()
		return verifyNbf(v, cmp, req)
	}
	return !req
}

// Valid 方法用来验证标准claims是否合法，如果上面列出的某些claim未出现在token中
// 那么我们仍然认为该token是合法的
func (m MapClaims) Valid() error {
	vErr := new(ValidationError)
	now := TimeFunc().Unix()

	if !m.VerifyExpiresAt(now, false) {
		vErr.Inner = errors.New("token is expired")
		vErr.Errors |= ValidationErrorExpired
	}

	if !m.VerifyIssuedAt(now, false) {
		vErr.Inner = errors.New("token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if !m.VerifyNotBefore(now, false) {
		vErr.Inner = errors.New("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}
