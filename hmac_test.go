package jwt

import (
	"io/ioutil"
	"strings"
	"testing"

	"github.com/gotoxu/assert"
)

var hmacTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"web sample",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AmUus1JoLd_ZBRLipjgE4JYpo708f-3Gwm8q3XrmcAU",
		"HS256",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		true,
	},
	{
		"HS384",
		"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.0R356iZXLpQAlD793UIpuVtqjO_fETDzvIVIoXeTYqyfkjKb-sPq9nVHP216KinG",
		"HS384",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		true,
	},
	{
		"HS512",
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0.Y-x6Ld37HgYXEdqfm9b98TsRHH-usSUxK5BEivjiDZYD5-laWBb2KPoqugcBuxVxfE0pJOiAx_oznQVyycWUUw",
		"HS512",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		true,
	},
	{
		"web sample: invalid",
		"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXo",
		"HS256",
		map[string]interface{}{"iss": "joe", "exp": 1300819380, "http://example.com/is_root": true},
		false,
	},
}

var hmacTestKey, _ = ioutil.ReadFile("test/hmacTestKey")

func TestHMACSign(t *testing.T) {
	for _, data := range hmacTestData {
		if data.valid {
			parts := strings.Split(data.tokenString, ".")
			m := GetSigningMethod(data.alg)
			sig, err := m.Sign(strings.Join(parts[0:2], "."), hmacTestKey)
			assert.Nil(t, err)
			assert.DeepEqual(t, sig, parts[2])
		}
	}
}

func TestHMACVerify(t *testing.T) {
	for _, data := range hmacTestData {
		parts := strings.Split(data.tokenString, ".")

		m := GetSigningMethod(data.alg)
		err := m.Verify(strings.Join(parts[0:2], "."), parts[2], hmacTestKey)

		if data.valid {
			assert.Nil(t, err)
		}
		if !data.valid {
			assert.NotNil(t, err)
		}
	}
}

func BenchmarkHS256Signing(b *testing.B) {
	benchmarkSigning(b, HS256Method, hmacTestKey)
}

func BenchmarkHS384Signing(b *testing.B) {
	benchmarkSigning(b, HS384Method, hmacTestKey)
}

func BenchmarkHS512Signing(b *testing.B) {
	benchmarkSigning(b, HS512Method, hmacTestKey)
}

func benchmarkSigning(b *testing.B, method SigningMethod, key interface{}) {
	t := New(method)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := t.Generate(key); err != nil {
				b.Fatal(err)
			}
		}
	})
}
