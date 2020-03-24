// Copyright 2018 Northern.tech AS
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
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/deviceauth/keys"
	"github.com/mendersoftware/go-lib-micro/mongo/uuid"
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
				ID: uuid.Must(uuid.FromString(
					"00000000-0000-4000-8000-000000000000")),
				Subject: uuid.Must(uuid.FromString(
					"00000000-0000-4000-8000-000000000001")),
				Issuer: "Mender",
			},
			expiresInSec: 3600,
		},
		"ok, with tenant": {
			privKey: loadPrivKey("./testdata/private.pem", t),
			claims: Claims{
				ID: uuid.Must(uuid.FromString(
					"00000000-0000-4000-8000-000000000000")),
				Subject: uuid.Must(uuid.FromString(
					"00000000-0000-4000-8000-000000000001")),
				Issuer: "Mender",
				Tenant: "foobar",
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
			assert.Equal(t, tc.claims.Subject.String(), mc["sub"])
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

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdW" +
				"QiOiJNZW5kZXIiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLT" +
				"QwMDAtODAwMC0wMDAwMDAwMDAwMDAiLCJzdWIiOiIwMD" +
				"AwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMD" +
				"EiLCJpc3MiOiJNZW5kZXIiLCJleHAiOjQyOTQ5NjcyOT" +
				"UsImlhdCI6MTUxNjIzOTAyMiwic2NwIjoibWVuZGVyLi" +
				"oifQ.wmdoYM-DT0wMhOfMBAn1G5nOyp1ilt77NvZ-1Ct" +
				"-J1Mh4LvVP_7LFRRVqWkDcww_uIFGP_eFswRX2WUTi63" +
				"swHmtuKcWhsM8p5odnk9eOS4eXQf1dW13cNVBkXI-bsq" +
				"xcMI3WlA1x9Vuzs0ngwRNs-tcGKLUe-5TbTkEII42H9K" +
				"KRMn17Lb1dgPWVS5Nfea5zfzDD9P8XsKsKh3qWDFjrQz" +
				"o6GTlmsClAERvPlNB08vgVT1gWFYB5A8iweDhii6tUH1" +
				"S9NmhnySSECgMttQbEg42P0MmLS1tRkLuhdEyLg8IiKt" +
				"LdSNVA596ILymHni1-34Ya5weVteKJ5N3IBjwxA",
			outToken: Token{
				Claims: Claims{
					ID: uuid.Must(uuid.FromString(
						"00000000-0000-4000-8000-000000000000")),
					Subject: uuid.Must(uuid.FromString(
						"00000000-0000-4000-8000-000000000001")),
					Audience: "Mender",
					ExpiresAt: &Time{
						Time: time.Unix(4294967295, 0),
					},
					IssuedAt: &Time{
						Time: time.Unix(1516239022, 0),
					},
					Issuer: "Mender",
					Scope:  "mender.*",
				},
			},
		},
		"ok (some claims)": {
			privKey: key,

			inToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdG" +
				"kiOiIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMD" +
				"AwMDAwMDAiLCJzdWIiOiIwMDAwMDAwMC0wMDAwLTQwMD" +
				"AtODAwMC0wMDAwMDAwMDAwMDEiLCJpc3MiOiJNZW5kZX" +
				"IiLCJleHAiOjQyOTQ5NjcyOTUsImlhdCI6MTUxNjIzOT" +
				"AyMiwic2NwIjoibWVuZGVyLnVzZXJzLmluaXRpYWwuY3" +
				"JlYXRlIn0.XbNL4t6lE2MwQrA1N8n6LSYLRr9NwuO-13" +
				"QVlegli2C2WujsW5jo4iUV-NqzuhKQ5IiZnnt4b-nmS7" +
				"j6HqmLXRaN8HXJ45zySKZQCY2462EjCB2AtcNYIVXF_l" +
				"fOiczBayqFFDebFzP3yXt0HOerAQ_APgVUy2zVGuNK5L" +
				"z5ieWeWBobAar63Pe1m6oupm7BN4dbzW1dke9oa3pTym" +
				"0kIh8C-OqrqymhLRh3YY7UOhan-HArGbqhtKZbPNZfxP" +
				"1TAXrD9fUZ2Gl9tOc8uZvT_-xTtV2HR5fpEr24W_LNRN" +
				"91gB7jBv1b6jonezanF-t2NDjTqBn3DWm_VgOEB6o3lQ",

			outToken: Token{
				Claims: Claims{
					ID: uuid.Must(uuid.FromString(
						"00000000-0000-4000-8000-000000000000")),
					Subject: uuid.Must(uuid.FromString(
						"00000000-0000-4000-8000-000000000001")),
					ExpiresAt: &Time{
						Time: time.Unix(4294967295, 0),
					},
					IssuedAt: &Time{
						Time: time.Unix(1516239022, 0),
					},
					Issuer: "Mender",
					Scope:  "mender.users.initial.create",
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
