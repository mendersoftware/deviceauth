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
package main

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	mtest "github.com/mendersoftware/deviceauth/test"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func RestError(status string) string {
	msg, _ := json.Marshal(map[string]string{"error": status})
	return string(msg)
}

func makeMockApiHandler(t *testing.T, mocka *MockDevAuth) http.Handler {
	handlers := NewDevAuthApiHandler(mocka)
	assert.NotNil(t, handlers)

	app, err := handlers.GetApp()
	assert.NotNil(t, app)
	assert.NoError(t, err)

	api := rest.NewApi()
	api.SetApp(app)

	return api.MakeHandler()
}

// create an auth req that's optionally:
// - signed with an actual key
// - signed with a bogus test value
// - not signed at all
func makeAuthReq(payload interface{}, key *rsa.PrivateKey, signature string, t *testing.T) *http.Request {
	r := test.MakeSimpleRequest("POST", "http://1.2.3.4/api/0.1.0/auth_requests", payload)

	b, err := json.Marshal(payload)
	if err != nil {
		t.FailNow()
	}

	if signature != "" {
		r.Header.Set(HdrAuthReqSign, signature)
	} else if key != nil {
		sign := mtest.AuthReqSign(b, key, t)
		r.Header.Set(HdrAuthReqSign, string(sign))
	}

	return r
}

func TestApiDevAuthSubmitAuthReq(t *testing.T) {
	// enforce specific field naming in errors returned by API
	rest.ErrorFieldName = "error"

	privkey := mtest.LoadPrivKey("testdata/private.pem", t)
	pubkeyStr := mtest.LoadPubKeyStr("testdata/public.pem", t)

	testCases := []struct {
		req *http.Request

		devAuthToken string
		devAuthErr   error

		code int
		body string
	}{
		{
			//empty body
			makeAuthReq(nil, nil, "dontcare", t),
			"",
			nil,
			400,
			RestError("failed to decode auth request: unexpected end of JSON input"),
		},
		{
			//incomplete body
			makeAuthReq(
				map[string]interface{}{
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				privkey,
				"",
				t),
			"",
			nil,
			400,
			RestError("invalid auth request: id_data must be provided"),
		},
		{
			//incomplete body
			makeAuthReq(
				map[string]interface{}{
					"id_data":      "id-0001",
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				privkey,
				"",
				t),
			"",
			nil,
			400,
			RestError("invalid auth request: pubkey must be provided"),
		},
		{
			//incomplete body
			makeAuthReq(
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
				},
				privkey,
				"",
				t),
			"",
			nil,
			400,
			RestError("invalid auth request: seq_no must be provided"),
		},
		{
			//complete body, missing signature header
			makeAuthReq(
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				nil,
				"",
				t),
			"",
			nil,
			400,
			RestError("missing request signature header"),
		},
		{
			//complete body, invalid signature header
			makeAuthReq(
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				nil,
				"invalidsignature",
				t),
			"",
			nil,
			401,
			RestError("signature verification failed"),
		},
		{
			//complete body + signature, auth error
			makeAuthReq(
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				privkey,
				"",
				t),
			"",
			ErrDevAuthUnauthorized,
			401,
			RestError("unauthorized"),
		},
		{
			//complete body + signature, auth ok
			makeAuthReq(
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				privkey,
				"",
				t),
			"dummytoken",
			nil,
			200,
			"dummytoken",
		},
	}

	for _, tc := range testCases {
		devauth := MockDevAuth{
			mockSubmitAuthRequest: func(r *AuthReq) (string, error) {
				if tc.devAuthErr != nil {
					return "", tc.devAuthErr
				}
				return tc.devAuthToken, nil
			},
		}
		apih := makeMockApiHandler(t, &devauth)

		recorded := test.RunRequest(t, apih, tc.req)
		recorded.CodeIs(tc.code)
		recorded.BodyIs(tc.body)
	}
}
