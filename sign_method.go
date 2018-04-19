package jwt

import (
	"sync"
)

var signingMethods = map[string]SigningMethod{}
var signingMethodLock = new(sync.RWMutex)

// SigningMethod 是包装签名函数的接口
type SigningMethod interface {
	Verify(canonicalString string, signature string, key interface{}) error
	Sign(canonicalString string, key interface{}) (string, error)
	Algorithm() string
}

// RegisterSigningMethod 将签名接口的实现注册到系统中
// alg是签名算法
func RegisterSigningMethod(alg string, m SigningMethod) {
	signingMethodLock.Lock()
	defer signingMethodLock.Unlock()

	signingMethods[alg] = m
}

// GetSigningMethod 是从所有注册的签名方法对象中获取指定算法的签名对象
func GetSigningMethod(alg string) SigningMethod {
	signingMethodLock.RLock()
	defer signingMethodLock.RUnlock()

	if m, ok := signingMethods[alg]; ok {
		return m
	}

	return nil
}
