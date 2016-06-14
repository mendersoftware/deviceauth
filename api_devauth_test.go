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
	"errors"
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

func TestApiDevAuthUpdateStatusDevice(t *testing.T) {
	devs := map[string]struct {
		dev *Device
		err error
	}{
		"foo": {
			dev: &Device{
				Id:     "foo",
				PubKey: "foobar",
				Status: "accepted",
				IdData: "deadcafe",
			},
			err: nil,
		},
		"bar": {
			dev: nil,
			err: errors.New("processing failed"),
		},
	}

	mockaction := func(id string) error {
		d, ok := devs[id]
		if ok == false {
			return ErrDevNotFound
		}
		if d.err != nil {
			return d.err
		}
		return nil
	}
	devauth := MockDevAuth{
		mockAcceptDevice: mockaction,
		mockRejectDevice: mockaction,
	}

	apih := makeMockApiHandler(t, &devauth)
	// enforce specific field naming in errors returned by API
	rest.ErrorFieldName = "error"

	accstatus := DevAuthApiStatus{"accepted"}
	rejstatus := DevAuthApiStatus{"rejected"}

	tcases := []struct {
		req     *http.Request
		code    int
		body    string
		headers map[string]string
	}{
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status", nil),
			code: 400,
			body: RestError("failed to decode status data: JSON payload is empty"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status",
				DevAuthApiStatus{"foo"}),
			code: 400,
			body: RestError("incorrect device status"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status",
				accstatus),
			code: 303,
			headers: map[string]string{
				"Location": "http://1.2.3.4/api/0.1.0/devices/foo",
			},
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/bar/status",
				accstatus),
			code: 500,
			body: RestError(devs["bar"].err.Error()),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/baz/status",
				accstatus),
			code: 404,
			body: RestError(ErrDevNotFound.Error()),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status",
				rejstatus),
			code: 303,
			headers: map[string]string{
				"Location": "http://1.2.3.4/api/0.1.0/devices/foo",
			},
		},
	}

	for _, tc := range tcases {
		recorded := test.RunRequest(t, apih, tc.req)
		recorded.CodeIs(tc.code)
		recorded.BodyIs(tc.body)
		for h, v := range tc.headers {
			recorded.HeaderIs(h, v)
		}
	}

}
