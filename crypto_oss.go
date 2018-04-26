package jwt

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
)

func init() {
	crypto.RegisterHash(crypto.SHA256, sha256.New)
	crypto.RegisterHash(crypto.SHA384, sha512.New384)
	crypto.RegisterHash(crypto.SHA512, sha512.New)
}
