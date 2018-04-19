package jwt

import "errors"

// Error constants
var (
	ErrInvalidKeyType   = errors.New("key is of invalid type")
	ErrSignatureInvalid = errors.New("signature is invalid")
)

// 这些错误会在转换或验证token时发生
const (
	ValidationErrorMalformed uint32 = 1 << iota
	ValidationErrorUnverifiable
	ValidationErrorSignatureInvalid
	ValidationErrorAudience
	ValidationErrorExpired
	ValidationErrorIssuedAt
	ValidationErrorIssuer
	ValidationErrorNotValidYet
	ValidationErrorID
	ValidationErrorClaimsInvalid
)

// NewValidationError 使用给定的错误消息创建一个ValidationError对象
func NewValidationError(errorText string, errorFlags uint32) *ValidationError {
	return &ValidationError{
		text:   errorText,
		Errors: errorFlags,
	}
}

// ValidationError 在转换或验证token失败时发生
type ValidationError struct {
	Inner  error
	Errors uint32
	text   string
}

func (e ValidationError) Error() string {
	if e.Inner != nil {
		return e.Inner.Error()
	} else if e.text != "" {
		return e.text
	} else {
		return "token is invalid"
	}
}

func (e *ValidationError) valid() bool {
	return e.Errors == 0
}
