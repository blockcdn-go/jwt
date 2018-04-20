package jwt

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/gotoxu/assert"
)

var (
	defaultKeyFunc KeyFunc = func(t *Token) (interface{}, error) { return ioutil.ReadFile("test/hmacTestKey") }
)

var jwtTestData = []struct {
	name       string
	tokeString string
	keyFunc    KeyFunc
	claims     Claims
	valid      bool
	errors     uint32
	parser     *Parser
}{
	{
		"basic",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqYXIiOiJiYXIifQ.EamOy0rENGDaNHrEQ0lImTz0e2LK32rYDbhT_NXqMTc",
		defaultKeyFunc,
		MapClaims{"jar": "bar"},
		true,
		0,
		nil,
	},
	{
		"basic expired",
		"",
		defaultKeyFunc,
		MapClaims{"foo": "bar", "exp": float64(time.Now().Unix() - 100)},
		false,
		ValidationErrorExpired,
		nil,
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
		"JSON Number - basic expired",
		"",
		defaultKeyFunc,
		MapClaims{"foo": "bar", "exp": json.Number(fmt.Sprintf("%v", time.Now().Unix()-100))},
		false,
		ValidationErrorExpired,
		&Parser{UseJSONNumber: true},
	},
	{
		"JSON Number - basic nbf",
		"",
		defaultKeyFunc,
		MapClaims{"foo": "bar", "nbf": json.Number(fmt.Sprintf("%v", time.Now().Unix()+100))},
		false,
		ValidationErrorNotValidYet,
		&Parser{UseJSONNumber: true},
	},
}

func TestParser_Parse(t *testing.T) {
	for _, data := range jwtTestData {
		if data.tokeString == "" {
			data.tokeString, _ = NewWithClaims(HS256Method, data.claims).Generate(hmacTestKey)
		}

		parser := data.parser
		if parser == nil {
			parser = new(Parser)
		}

		var token *Token
		var err error

		switch data.claims.(type) {
		case MapClaims:
			token, err = parser.ParseWithClaims(data.tokeString, MapClaims{}, data.keyFunc)
		case *StandardClaims:
			token, err = parser.ParseWithClaims(data.tokeString, &StandardClaims{}, data.keyFunc)
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
