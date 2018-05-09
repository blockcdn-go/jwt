package jwt

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/gotoxu/assert"
)

var errKeyFunc = fmt.Errorf("error loading key")

var (
	jwtTestDefaultKey *rsa.PublicKey
	defaultKeyFunc    KeyFunc = func(t *Token) (interface{}, error) { return jwtTestDefaultKey, nil }
	emptyKeyFunc      KeyFunc = func(t *Token) (interface{}, error) { return nil, nil }
	errorKeyFunc      KeyFunc = func(t *Token) (interface{}, error) { return nil, errKeyFunc }
	nilKeyFunc        KeyFunc
)

func init() {
	jwtTestDefaultKey = loadRSAPublicKeyFromDisk("test/sample_key.pub")
}

func loadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func loadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func makeSampleToken(c Claims, key interface{}) string {
	token := NewWithClaims(RS256, c)
	s, e := token.Generate(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}

var jwtTestData = []struct {
	name        string
	tokenString string
	keyfunc     KeyFunc
	claims      Claims
	valid       bool
	errors      uint32
	parser      *Parser
}{
	{
		"basic",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		true,
		0,
		nil,
	},
	{
		"basic expired",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		ValidationErrorExpired,
		nil,
	},
	{
		"basic nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100)},
		false,
		ValidationErrorNotValidYet,
		nil,
	},
	{
		"expired and nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": float64(time.Now().Unix() + 100), "exp": float64(time.Now().Unix() - 100)},
		false,
		ValidationErrorNotValidYet | ValidationErrorExpired,
		nil,
	},
	{
		"basic invalid",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.EhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic nokeyfunc",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		nilKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorUnverifiable,
		nil,
	},
	{
		"basic nokey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		emptyKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorSignatureInvalid,
		nil,
	},
	{
		"basic errorkey",
		"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJmb28iOiJiYXIifQ.FhkiHkoESI_cG3NPigFrxEk9Z60_oXrOT2vGm9Pn6RDgYNovYORQmmA0zs1AoAOf09ly2Nx2YAg6ABqAYga1AcMFkJljwxTT5fYphTuqpWdy4BELeSYJx5Ty2gmr8e7RonuUztrdD5WfPqLKMm1Ozp_T6zALpRmwTIW0QPnaBXaQD90FplAg46Iy1UlDKr-Eupy0i5SLch5Q-p2ZpaL_5fnTIUDlxC3pWhJTyx_71qDI-mAA_5lE_VdroOeflG56sSmDxopPEG3bFlSu1eowyBfxtu0_CuVd-M42RU75Zc4Gsj6uV77MBtbMrf4_7M_NUTSgoIF3fRqxrj0NzihIBg",
		errorKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorUnverifiable,
		nil,
	},
	{
		"invalid signing method",
		"",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		false,
		ValidationErrorSignatureInvalid,
		&Parser{ValidMethods: []string{"HS256"}},
	},
	{
		"valid signing method",
		"",
		defaultKeyFunc,
		MapClaims{"foo": "bar"},
		true,
		0,
		&Parser{ValidMethods: []string{"RS256", "HS256"}},
	},
	{
		"JSON Number",
		"",
		defaultKeyFunc,
		MapClaims{"foo": json.Number("123.4")},
		true,
		0,
		&Parser{UseJSONNumber: true},
	},
	{
		"Standard Claims",
		"",
		defaultKeyFunc,
		&StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * 10).Unix(),
		},
		true,
		0,
		&Parser{UseJSONNumber: true},
	},
	{
		"Standard Claims",
		"",
		defaultKeyFunc,
		StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * 10).Unix(),
		},
		true,
		0,
		&Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - basic expired",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		ValidationErrorExpired,
		&Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - basic nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		false,
		ValidationErrorNotValidYet,
		&Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - expired and nbf",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100)), "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		ValidationErrorNotValidYet | ValidationErrorExpired,
		&Parser{UseJSONNumber: true},
	},
	{
		"SkipClaimsValidation during token parsing",
		"", // autogen
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		true,
		0,
		&Parser{UseJSONNumber: true, SkipClaimsValidation: true},
	},
}

func TestParser_Parse(t *testing.T) {
	privateKey := loadRSAPrivateKeyFromDisk("test/sample_key")

	for _, data := range jwtTestData {
		if data.tokenString == "" {
			data.tokenString = makeSampleToken(data.claims, privateKey)
		}

		parser := data.parser
		if parser == nil {
			parser = new(Parser)
		}

		var token *Token
		var err error

		switch data.claims.(type) {
		case MapClaims:
			token, err = parser.ParseWithClaims(data.tokenString, MapClaims{}, data.keyfunc)
		case *StandardClaims:
			token, err = parser.ParseWithClaims(data.tokenString, &StandardClaims{}, data.keyfunc)
		case StandardClaims:
			token, err = parser.ParseWithClaims(data.tokenString, StandardClaims{}, data.keyfunc)
		}

		assert.DeepEqual(t, token.Claims, data.claims)
		if data.valid {
			assert.Nil(t, err)
		}
		if !data.valid {
			assert.NotNil(t, err)
		}

		if data.valid {
			assert.NotEmpty(t, token.Signature)
		}
	}
}
