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
	"net/http"
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/deviceauth/requestid"
	"github.com/mendersoftware/deviceauth/requestlog"
	mtest "github.com/mendersoftware/deviceauth/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func RestError(status string) string {
	msg, _ := json.Marshal(map[string]interface{}{"error": status, "request_id": "test"})
	return string(msg)
}

func runTestRequest(t *testing.T, handler http.Handler, req *http.Request, code int, body string) *test.Recorded {
	req.Header.Add(requestid.RequestIdHeader, "test")
	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(code)
	recorded.BodyIs(body)
	return recorded
}

func makeMockApiHandler(t *testing.T, f DevAuthFactory) http.Handler {
	handlers := NewDevAuthApiHandler(f)
	assert.NotNil(t, handlers)

	app, err := handlers.GetApp()
	assert.NotNil(t, app)
	assert.NoError(t, err)

	api := rest.NewApi()
	api.Use(
		&requestlog.RequestLogMiddleware{},
		&requestid.RequestIdMiddleware{},
	)
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
			//complete body, missing signature header
			makeAuthReq(
				map[string]interface{}{
					"id_data":      "id-0001",
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
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
		devauth := MockDevAuthApp{}
		devauth.On("SubmitAuthRequest", mock.AnythingOfType("*main.AuthReq")).Return(
			func(r *AuthReq) string {
				if tc.devAuthErr != nil {
					return ""
				}
				return tc.devAuthToken
			},
			tc.devAuthErr)

		devauth.On("WithContext", mock.AnythingOfType("*main.RequestContext")).Return(&devauth)

		factory := func(l *log.Logger) (DevAuthApp, error) {
			return &devauth, nil
		}

		apih := makeMockApiHandler(t, factory)

		recorded := runTestRequest(t, apih, tc.req, tc.code, tc.body)
		if tc.code == http.StatusOK {
			assert.Equal(t, "application/jwt", recorded.Recorder.HeaderMap.Get("Content-Type"))
		}
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
	devauth := MockDevAuthApp{}
	devauth.On("AcceptDevice", mock.AnythingOfType("string")).Return(mockaction)
	devauth.On("RejectDevice", mock.AnythingOfType("string")).Return(mockaction)
	devauth.On("ResetDevice", mock.AnythingOfType("string")).Return(mockaction)
	devauth.On("WithContext", mock.AnythingOfType("*main.RequestContext")).Return(&devauth)

	factory := func(l *log.Logger) (DevAuthApp, error) {
		return &devauth, nil
	}

	apih := makeMockApiHandler(t, factory)
	// enforce specific field naming in errors returned by API
	rest.ErrorFieldName = "error"

	accstatus := DevAuthApiStatus{"accepted"}
	rejstatus := DevAuthApiStatus{"rejected"}
	penstatus := DevAuthApiStatus{"pending"}

	tcases := []struct {
		req  *http.Request
		code int
		body string
	}{
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status", nil),
			code: http.StatusBadRequest,
			body: RestError("failed to decode status data: JSON payload is empty"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status",
				DevAuthApiStatus{"foo"}),
			code: http.StatusBadRequest,
			body: RestError("incorrect device status"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status",
				accstatus),
			code: http.StatusNoContent,
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/bar/status",
				accstatus),
			code: http.StatusInternalServerError,
			body: RestError("internal error"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/baz/status",
				accstatus),
			code: http.StatusNotFound,
			body: RestError(ErrDevNotFound.Error()),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status",
				rejstatus),
			code: http.StatusNoContent,
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/0.1.0/devices/foo/status",
				penstatus),
			code: http.StatusNoContent,
		},
	}

	for idx, tc := range tcases {
		t.Logf("running %d", idx)
		runTestRequest(t, apih, tc.req, tc.code, tc.body)
	}

}

func TestApiDevAuthVerifyToken(t *testing.T) {
	// enforce specific field naming in errors returned by API
	rest.ErrorFieldName = "error"

	tcases := []struct {
		req     *http.Request
		code    int
		body    string
		headers map[string]string
		err     error
	}{
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/0.1.0/tokens/verify", nil),
			code: http.StatusUnauthorized,
			body: RestError(ErrNoAuthHeader.Error()),
			err:  nil,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/0.1.0/tokens/verify", nil),
			code: 200,
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: nil,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/0.1.0/tokens/verify", nil),
			code: http.StatusForbidden,
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: ErrTokenExpired,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/0.1.0/tokens/verify", nil),
			code: http.StatusUnauthorized,
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: ErrTokenInvalid,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/0.1.0/tokens/verify", nil),
			code: 500,
			body: RestError("internal error"),
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: errors.New("some error that will only be logged"),
		},
	}

	for _, tc := range tcases {
		devauth := MockDevAuthApp{}
		devauth.On("VerifyToken", mock.AnythingOfType("string")).Return(tc.err)

		factory := func(l *log.Logger) (DevAuthApp, error) {
			return &devauth, nil
		}
		apih := makeMockApiHandler(t, factory)
		if len(tc.headers) > 0 {
			tc.req.Header.Set("authorization", tc.headers["authorization"])
		}
		runTestRequest(t, apih, tc.req, tc.code, tc.body)
	}

}

func TestApiDevAuthDeleteToken(t *testing.T) {
	// enforce specific field naming in errors returned by API
	rest.ErrorFieldName = "error"

	tcases := []struct {
		req  *http.Request
		code int
		body string
		err  error
	}{
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/0.1.0/tokens/foo", nil),
			code: http.StatusNoContent,
			err:  nil,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/0.1.0/tokens/foo", nil),
			code: http.StatusNotFound,
			err:  ErrTokenNotFound,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/0.1.0/tokens/foo", nil),
			code: http.StatusInternalServerError,
			body: RestError("internal error"),
			err:  errors.New("some error that will only be logged"),
		},
	}

	for _, tc := range tcases {
		devauth := MockDevAuthApp{}
		devauth.On("RevokeToken", mock.AnythingOfType("string")).Return(tc.err)

		factory := func(l *log.Logger) (DevAuthApp, error) {
			return &devauth, nil
		}
		apih := makeMockApiHandler(t, factory)
		runTestRequest(t, apih, tc.req, tc.code, tc.body)
	}

}
