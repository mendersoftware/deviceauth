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
	"encoding/json"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
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

func makeReq(method, url string, body interface{}, hdr map[string]string) *http.Request {
	req := test.MakeSimpleRequest(method, url, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req
}

func TestApiDevAuthSubmitAuthReq(t *testing.T) {
	//sig hdr
	//req body x fields
	//devauth res x 2

	// enforce specific field naming in errors returned by API
	rest.ErrorFieldName = "error"

	testCases := []struct {
		req *http.Request

		devAuthToken string
		devAuthErr   error

		code int
		body string
	}{
		//empty body
		{
			makeReq("POST",
				"http://1.2.3.4/api/0.1.0/auth_requests",
				nil,
				nil),
			"",
			nil,
			400,
			RestError("failed to decode auth request: unexpected end of JSON input"),
		},
		//incomplete body
		{
			makeReq("POST",
				"http://1.2.3.4/api/0.1.0/auth_requests",
				map[string]interface{}{
					"pubkey":       "key-0001",
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				nil),
			"",
			nil,
			400,
			RestError("invalid auth request: id_data must be provided"),
		},
		//incomplete body
		{
			makeReq("POST",
				"http://1.2.3.4/api/0.1.0/auth_requests",
				map[string]interface{}{
					"id_data":      "id-0001",
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				nil),
			"",
			nil,
			400,
			RestError("invalid auth request: pubkey must be provided"),
		},
		//incomplete body
		{
			makeReq("POST",
				"http://1.2.3.4/api/0.1.0/auth_requests",
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       "key-0001",
					"tenant_token": "tenant-0001",
				},
				nil),
			"",
			nil,
			400,
			RestError("invalid auth request: seq_no must be provided"),
		},
		//complete body, no signature header
		{
			makeReq("POST",
				"http://1.2.3.4/api/0.1.0/auth_requests",
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       "key-0001",
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				nil),
			"",
			nil,
			400,
			RestError("missing request signature header"),
		},
		//complete body + signature, auth error
		{
			makeReq("POST",
				"http://1.2.3.4/api/0.1.0/auth_requests",
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       "key-0001",
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				map[string]string{
					hdrAuthReqSign: "dontcare"}),
			"",
			ErrDevAuthUnauthorized,
			401,
			RestError("unauthorized"),
		},
		//complete body + signature, auth ok
		{
			makeReq("POST",
				"http://1.2.3.4/api/0.1.0/auth_requests",
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       "key-0001",
					"tenant_token": "tenant-0001",
					"seq_no":       1,
				},
				map[string]string{
					hdrAuthReqSign: "dontcare"}),
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
