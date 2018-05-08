package jwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// KeyFunc Parse方法使用此回调函数提供验证密钥。
// 该函数接受已转换但未验证的Token作为参数。
// 因此你可以根据令牌头部中的属性来决定使用哪个密钥
type KeyFunc func(*Token) (interface{}, error)

// Parser 是JWT Token string的转换器
// 可以将字符串转换为Token对象
type Parser struct {
	ValidMethods         []string
	UseJSONNumber        bool
	SkipClaimsValidation bool
}

// Parse 转换，验证并返回一个Token对象
func (p *Parser) Parse(tokenString string, keyFunc KeyFunc) (*Token, error) {
	return p.ParseWithClaims(tokenString, MapClaims{}, keyFunc)
}

// ParseWithClaims 转换，验证并返回一个Token对象
func (p *Parser) ParseWithClaims(tokenString string, claims Claims, keyFunc KeyFunc) (*Token, error) {
	token, parts, err := p.ParseUnverified(tokenString, claims)
	if err != nil {
		return token, err
	}

	if p.ValidMethods != nil {
		var signingMethodValid = false
		var alg = token.Method.Algorithm()
		for _, m := range p.ValidMethods {
			if m == alg {
				signingMethodValid = true
				break
			}
		}
		if !signingMethodValid {
			return token, NewValidationError(fmt.Sprintf("signing method %v is invalid", alg), ValidationErrorSignatureInvalid)
		}
	}

	var key interface{}
	if keyFunc == nil {
		return token, NewValidationError("no Keyfunc was provided", ValidationErrorUnverifiable)
	}

	if key, err = keyFunc(token); err != nil {
		if ve, ok := err.(*ValidationError); ok {
			return token, ve
		}
		return token, &ValidationError{Inner: err, Errors: ValidationErrorUnverifiable}
	}

	vErr := &ValidationError{}

	if !p.SkipClaimsValidation {
		if err := token.Claims.Valid(); err != nil {
			if e, ok := err.(*ValidationError); !ok {
				vErr = &ValidationError{Inner: err, Errors: ValidationErrorClaimsInvalid}
			} else {
				vErr = e
			}
		}
	}

	token.Signature = parts[2]
	if err = token.Method.Verify(strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		vErr.Inner = err
		vErr.Errors |= ValidationErrorSignatureInvalid
	}

	if vErr.valid() {
		token.Valid = true
		return token, nil
	}

	return token, vErr
}

// ParseUnverified 转换令牌但并不验证令牌签名
func (p *Parser) ParseUnverified(tokenString string, claims Claims) (token *Token, parts []string, err error) {
	parts = strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, parts, NewValidationError("token contains an invalid number of segments", ValidationErrorMalformed)
	}

	token = &Token{Raw: tokenString}

	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return token, parts, NewValidationError("tokenstring should not contain 'bearer '", ValidationErrorMalformed)
		}
		return token, parts, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}

	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return token, parts, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}

	var claimBytes []byte
	token.Claims = claims

	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return token, parts, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
	}

	dec := json.NewDecoder(bytes.NewBuffer(claimBytes))
	if p.UseJSONNumber {
		dec.UseNumber()
	}

	if c, ok := token.Claims.(MapClaims); ok {
		err = dec.Decode(&c)
		if err != nil {
			return token, parts, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
		}
		token.Claims = c
	} else if c, ok := token.Claims.(StandardClaims); ok {
		err = dec.Decode(&c)
		if err != nil {
			return token, parts, &ValidationError{Inner: err, Errors: ValidationErrorMalformed}
		}
		token.Claims = c
	} else {
		return token, parts, &ValidationError{Inner: err, Errors: ValidationErrorClaimsType}
	}

	if method, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(method); token.Method == nil {
			return token, parts, NewValidationError("signing method (alg) is unavailable.", ValidationErrorUnverifiable)
		}
	} else {
		return token, parts, NewValidationError("signing method (alg) is unspecified.", ValidationErrorUnverifiable)
	}

	return token, parts, nil
}
