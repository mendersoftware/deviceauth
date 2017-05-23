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
	"testing"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/deviceauth/keys"
)

func TestNewJWTHandlerRS256(t *testing.T) {
	privKey := loadPrivKey("./testdata/private.pem", t)
	jwtHandler := NewJWTHandlerRS256(privKey)

	assert.NotNil(t, jwtHandler)
}

func TestJWTHandlerRS256GenerateToken(t *testing.T) {
	testCases := map[string]struct {
		privKey      *rsa.PrivateKey
		claims       Claims
		expiresInSec int64
	}{
		"ok": {
			privKey: loadPrivKey("./testdata/private.pem", t),
			claims: Claims{
				Issuer:  "Mender",
				Subject: "foo",
			},
			expiresInSec: 3600,
		},
		"ok, with tenant": {
			privKey: loadPrivKey("./testdata/private.pem", t),
			claims: Claims{
				Issuer:  "Mender",
				Subject: "foo",
				Tenant:  "foobar",
			},
			expiresInSec: 3600,
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)
		jwtHandler := NewJWTHandlerRS256(tc.privKey)

		raw, err := jwtHandler.ToJWT(&Token{
			Claims: tc.claims,
		})
		assert.NoError(t, err)

		parsed := parseGeneratedTokenRS256(t, string(raw), tc.privKey)
		if assert.NotNil(t, parsed) {
			mc := parsed.Claims.(jwtgo.MapClaims)
			assert.Equal(t, tc.claims.Issuer, mc["iss"])
			assert.Equal(t, tc.claims.Subject, mc["sub"])
			if tc.claims.Tenant != "" {
				assert.Equal(t, tc.claims.Tenant, mc["mender.tenant"])
			} else {
				assert.Nil(t, mc["mender.tenant"])
			}
		}
	}
}

func TestJWTHandlerRS256FromJWT(t *testing.T) {

	key := loadPrivKey("./testdata/private.pem", t)

	testCases := map[string]struct {
		privKey *rsa.PrivateKey

		inToken string

		outToken Token
		outErr   error
	}{
		"ok (all claims)": {
			privKey: key,

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJhdWQiOiJNZW5kZXIiLCJleHAiOjIxNDc0ODM2NDcsImp" +
				"0aSI6InNvbWVpZCIsImlhdCI6MTIzNDU2NywiaXNzIjoiTW" +
				"VuZGVyIiwibmJmIjoxMjM0NTY3OCwic3ViIjoiZm9vIiwic" +
				"2NwIjoibWVuZGVyLioifQ.TqIWTOA6VE0dEGkjX3ilv0vhK" +
				"YdSDvnK5E9qKL8uDyheVOvDRXse4OnDhyaEuAQVfQhh2DMW" +
				"S-B3bGfWP8-tKvrbmGxHw1-B6vz_QePBmEq4RPGYPxUFxN2" +
				"69blmAV9_56FhKa1Tl1CyqA9riHAtxFXYZW5RvpaQd7Q5Ja" +
				"SvN_csRsEWFwD8ZC_kzUfBosfiVJLll0KH0EGlpezzBYilT" +
				"wB8C92CAY9s916kIfXHWn9lPsESGW5uURL7Fbj9-G5OT7WO" +
				"DDU0bYwLpBbtdw5hNUi9ExnX2SfW3HpD7wuxM3J_q_aEu6Q" +
				"efs-sTDG1iKG4KFCszfmEV8p0HqPNC3VpEw",

			outToken: Token{
				Claims: Claims{
					Audience:  "Mender",
					ExpiresAt: 2147483647,
					ID:        "someid",
					IssuedAt:  1234567,
					Issuer:    "Mender",
					NotBefore: 12345678,
					Subject:   "foo",
					Scope:     "mender.*",
				},
			},
		},
		"ok (some claims)": {
			privKey: key,

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJle" +
				"HAiOjIxNDc0ODM2NDcsImp0aSI6InNvbWVpZCIsIml" +
				"hdCI6MTIzNDU2NywiaXNzIjoiTWVuZGVyIiwic3ViI" +
				"joiZm9vIiwic2NwIjoibWVuZGVyLnVzZXJzLmluaXR" +
				"pYWwuY3JlYXRlIn0.xkcfTeUui66Cib1c0bO27I_LD" +
				"C60WlxzB8v6PuH8EGqgCeU3RG6nW5tf-YcS9w17-Qt" +
				"1jWs-RSpQip3VWQqncSbfzUjmwKuTgrMRllILb5hMP" +
				"8trVSl4r035WxPd1Gk8chtbZra9dh7Wf9LsOCjamrX" +
				"baSE-w64iFFShHrgW_e9TqRcnb8c37XLeHnxRHSYkL" +
				"QGwPWm6jaxr08mR6-vYxgEIFpTUxVbxe1AN8hMZq43" +
				"x-KQb3su4EoGMT6KM_ku3P8Tmk8l3yewZdgEuZc-T7" +
				"tsSlEMgLwcrQSF2jyfHewBsc40iHIxmO3ibNFITzw_CwaDidlHSLkSMk3EMCis1gA",

			outToken: Token{
				Claims: Claims{
					ExpiresAt: 2147483647,
					ID:        "someid",
					IssuedAt:  1234567,
					Issuer:    "Mender",
					Subject:   "foo",
					Scope:     "mender.users.initial.create",
				},
			},
		},
		"error - token invalid": {
			privKey: key,

			inToken: "1234123412341234",

			outToken: Token{},
			outErr:   errors.New("token contains an invalid number of segments"),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)
		jwtHandler := NewJWTHandlerRS256(tc.privKey)

		token, err := jwtHandler.FromJWT(tc.inToken)
		if tc.outErr == nil {
			assert.NoError(t, err)
			assert.Equal(t, tc.outToken, *token)
		} else {
			assert.EqualError(t, tc.outErr, err.Error())
		}
	}
}

func loadPrivKey(path string, t *testing.T) *rsa.PrivateKey {
	key, err := keys.LoadRSAPrivate(path)
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}

	return key
}

func parseGeneratedTokenRS256(t *testing.T, token string, key *rsa.PrivateKey) *jwtgo.Token {
	tokenParsed, err := jwtgo.Parse(token, func(token *jwtgo.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, errors.New("Unexpected signing method: " + token.Method.Alg())
		}
		return &key.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("can't parse token: %s", err.Error())
	}

	return tokenParsed
}
