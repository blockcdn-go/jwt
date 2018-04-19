package jwt

import "errors"

// Error constants
var (
	ErrInvalidKeyType   = errors.New("key is of invalid type")
	ErrSignatureInvalid = errors.New("signature is invalid")
)
