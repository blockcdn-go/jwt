package jwt

import (
	"io/ioutil"
	"strings"
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gotoxu/assert"
)

var rsaTestData = []struct {
	name        string
	tokenString string
	alg         string
	claims      map[string]interface{}
	valid       bool
}{
	{
		"Basic RS256",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"RS256",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic RS384",
		"eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.W-jEzRfBigtCWsinvVVuldiuilzVdU5ty0MvpLaSaqK9PlAWWlDQ1VIQ_qSKzwL5IXaZkvZFJXT3yL3n7OUVu7zCNJzdwznbC8Z-b0z2lYvcklJYi2VOFRcGbJtXUqgjk2oGsiqUMUMOLP70TTefkpsgqDxbRh9CDUfpOJgW-dU7cmgaoswe3wjUAUi6B6G2YEaiuXC0XScQYSYVKIzgKXJV8Zw-7AN_DBUI4GkTpsvQ9fVVjZM9csQiEXhYekyrKu1nu_POpQonGd8yqkIyXPECNmmqH5jH4sFiF67XhD7_JpkvLziBpI-uh86evBUadmHhb9Otqw3uV3NTaXLzJw",
		"RS384",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"Basic RS512",
		"eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.zBlLlmRrUxx4SJPUbV37Q1joRcI9EW13grnKduK3wtYKmDXbgDpF1cZ6B-2Jsm5RB8REmMiLpGms-EjXhgnyh2TSHE-9W2gA_jvshegLWtwRVDX40ODSkTb7OVuaWgiy9y7llvcknFBTIg-FnVPVpXMmeV_pvwQyhaz1SSwSPrDyxEmksz1hq7YONXhXPpGaNbMMeDTNP_1oj8DZaqTIL9TwV8_1wb2Odt_Fy58Ke2RVFijsOLdnyEAjt2n9Mxihu9i3PhNBkkxa2GbnXBfq3kzvZ_xxGGopLdHhJjcGWXO-NiwI9_tiu14NRv4L2xC0ItD9Yz68v2ZIZEp_DuzwRQ",
		"RS512",
		map[string]interface{}{"foo": "bar"},
		true,
	},
	{
		"basic invalid: foo => bar",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		"RS256",
		map[string]interface{}{"foo": "bar"},
		false,
	},
}

func TestRSASign(t *testing.T) {
	keyData, _ := ioutil.ReadFile("test/sample_key")
	key, err := ParseRSAPrivateKeyFromPEM(keyData)
	assert.Nil(t, err)

	for _, data := range rsaTestData {
		if data.valid {
			parts := strings.Split(data.tokenString, ".")

			method := GetSigningMethod(data.alg)
			sig, err := method.Sign(strings.Join(parts[0:2], "."), key)
			assert.Nil(t, err)
			assert.DeepEqual(t, sig, parts[2])
		}
	}
}

func TestRSAVerify(t *testing.T) {
	keyData, _ := ioutil.ReadFile("test/sample_key.pub")
	key, err := ParseRSAPublicKeyFromPEM(keyData)
	assert.Nil(t, err)

	for _, data := range rsaTestData {
		parts := strings.Split(data.tokenString, ".")

		method := GetSigningMethod(data.alg)
		err := method.Verify(strings.Join(parts[0:2], "."), parts[2], key)
		if data.valid {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}
	}
}

func TestRSAKeyParsing(t *testing.T) {
	key, _ := ioutil.ReadFile("test/sample_key")
	secureKey, _ := ioutil.ReadFile("test/privateSecure.pem")
	pubKey, _ := ioutil.ReadFile("test/sample_key.pub")
	badKey := []byte("All your base are belong to key")

	var e error
	_, e = ParseRSAPrivateKeyFromPEM(key)
	assert.Nil(t, e)

	_, e = ParseRSAPrivateKeyFromPEM(pubKey)
	assert.NotNil(t, e)

	_, e = ParseRSAPrivateKeyFromPEM(badKey)
	assert.NotNil(t, e)

	_, e = ParseRSAPrivateKeyFromPEMWithPassword(secureKey, "password")
	assert.Nil(t, e)

	_, e = ParseRSAPrivateKeyFromPEMWithPassword(secureKey, "123132")
	assert.NotNil(t, e)

	_, e = ParseRSAPublicKeyFromPEM(pubKey)
	assert.Nil(t, e)

	_, e = ParseRSAPublicKeyFromPEM(key)
	assert.NotNil(t, e)

	_, e = ParseRSAPublicKeyFromPEM(badKey)
	assert.NotNil(t, e)
}

func BenchmarkRS256Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/sample_key")
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, RS256, parsedKey)
}

func BenchmarkRS384Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/sample_key")
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, RS384, parsedKey)
}

func BenchmarkRS512Signing(b *testing.B) {
	key, _ := ioutil.ReadFile("test/sample_key")
	parsedKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkSigning(b, RS512, parsedKey)
}
