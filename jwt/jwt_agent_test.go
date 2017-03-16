// Copyright 2016 Mender Software AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
package jwt

import (
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/mendersoftware/deviceauth/test"

	"github.com/stretchr/testify/assert"
)

func TestNewJWTAgent(t *testing.T) {
	t.Parallel()

	c := JWTAgentConfig{
		PrivateKey:        nil,
		ExpirationTimeout: 1234,
		Issuer:            "foo",
	}

	jwt := NewJWTAgent(c)
	assert.NotNil(t, jwt)
}

func TestGenerateTokenSignRS256(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		privKey *rsa.PrivateKey
		devId   string
	}{
		{
			privKey: test.LoadPrivKey("testdata/private.pem", t),
			devId:   "deviceId",
		},
	}
	for _, tc := range testCases {
		c := JWTAgentConfig{
			PrivateKey:        tc.privKey,
			Issuer:            "Mender",
			ExpirationTimeout: 1,
		}
		jwt := NewJWTAgent(c)
		token, err := jwt.GenerateTokenSignRS256(tc.devId)
		assert.NoError(t, err)
		assert.Equal(t, tc.devId, token.DevId)
	}
}

func TestValidateTokenSignRS256(t *testing.T) {
	t.Parallel()

	key := test.LoadPrivKey("testdata/private.pem", t)

	testCases := []struct {
		privKey    *rsa.PrivateKey
		devId      string
		expiration int64
		err        error
		delay      int64
	}{
		{
			privKey:    key,
			devId:      "deviceId",
			expiration: time.Now().Unix() + 123,
			err:        nil,
		},
		{
			privKey:    key,
			devId:      "deviceId",
			expiration: 0,
			err:        ErrTokenExpired,
			delay:      1,
		},
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			c := JWTAgentConfig{
				PrivateKey:        tc.privKey,
				Issuer:            "Mender",
				ExpirationTimeout: tc.expiration,
			}
			jwt := NewJWTAgent(c)
			token, err := jwt.GenerateTokenSignRS256(tc.devId)
			assert.NoError(t, err)
			assert.Equal(t, tc.devId, token.DevId)
			if tc.err == ErrTokenExpired {
				time.Sleep(time.Second * time.Duration(tc.delay))
			}
			_, err = jwt.ValidateTokenSignRS256(token.Token)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
			// assert jit is uuid v4?
		})
	}
}
