package jwt

import (
	"encoding/base64"
	"strings"
)

// EncodeSegment 按照JWT的编码规则为数据编码
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// DecodeSegment 按照JWT编码规则将数据解码为原始数据
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
