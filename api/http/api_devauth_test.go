// Copyright 2017 Northern.tech AS
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
package http

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/deviceauth/devauth"
	"github.com/mendersoftware/deviceauth/devauth/mocks"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	mtest "github.com/mendersoftware/deviceauth/utils/testing"
)

var restErrUpdateDone sync.Once

func updateRestErrorFieldName() {
	restErrUpdateDone.Do(func() {
		rest.ErrorFieldName = "error"
	})
}

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

func makeMockApiHandler(t *testing.T, da devauth.App) http.Handler {
	handlers := NewDevAuthApiHandlers(da)
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
	r := test.MakeSimpleRequest("POST",
		"http://1.2.3.4/api/devices/v1/authentication/auth_requests",
		payload)

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
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

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
			devauth.ErrDevAuthUnauthorized,
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
		{
			//complete body + signature, auth ok, tenant token empty
			makeAuthReq(
				map[string]interface{}{
					"id_data": "id-0001",
					"pubkey":  pubkeyStr,
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

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			da := &mocks.App{}
			da.On("SubmitAuthRequest",
				mtest.ContextMatcher(),
				mock.AnythingOfType("*model.AuthReq")).
				Return(
					func(_ context.Context, r *model.AuthReq) string {
						if tc.devAuthErr != nil {
							return ""
						}
						return tc.devAuthToken
					},
					tc.devAuthErr)

			apih := makeMockApiHandler(t, da)

			recorded := runTestRequest(t, apih, tc.req, tc.code, tc.body)
			if tc.code == http.StatusOK {
				assert.Equal(t, "application/jwt",
					recorded.Recorder.HeaderMap.Get("Content-Type"))
			}
		})
	}
}

func TestApiDevAuthUpdateStatusDevice(t *testing.T) {
	t.Parallel()

	devs := map[string]struct {
		dev *model.Device
		err error
	}{
		"123,456": {
			dev: &model.Device{
				Id:     "foo",
				PubKey: "foobar",
				Status: "accepted",
				IdData: "deadcafe",
			},
			err: nil,
		},
		"234,567": {
			dev: nil,
			err: devauth.ErrDevIdAuthIdMismatch,
		},
		"345,678": {
			dev: nil,
			err: errors.New("processing failed"),
		},
	}

	mockaction := func(_ context.Context, dev_id string, auth_id string) error {
		d, ok := devs[dev_id+","+auth_id]
		if ok == false {
			return store.ErrDevNotFound
		}
		if d.err != nil {
			return d.err
		}
		return nil
	}
	da := &mocks.App{}
	da.On("AcceptDeviceAuth",
		mtest.ContextMatcher(),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string")).Return(mockaction)
	da.On("RejectDeviceAuth",
		mtest.ContextMatcher(),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string")).Return(mockaction)
	da.On("ResetDeviceAuth",
		mtest.ContextMatcher(),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("string")).Return(mockaction)

	apih := makeMockApiHandler(t, da)
	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

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
				"http://1.2.3.4/api/management/v1/devauth/devices/123/auth/456/status", nil),
			code: http.StatusBadRequest,
			body: RestError("failed to decode status data: JSON payload is empty"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/123/auth/456/status",
				DevAuthApiStatus{"foo"}),
			code: http.StatusBadRequest,
			body: RestError("incorrect device status"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/123/auth/456/status",
				accstatus),
			code: http.StatusNoContent,
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/345/auth/678/status",
				accstatus),
			code: http.StatusInternalServerError,
			body: RestError("internal error"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/999/auth/123/status",
				accstatus),
			code: http.StatusNotFound,
			body: RestError(store.ErrDevNotFound.Error()),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/123/auth/456/status",
				rejstatus),
			code: http.StatusNoContent,
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/123/auth/456/status",
				penstatus),
			code: http.StatusNoContent,
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/234/auth/567/status",
				penstatus),
			code: http.StatusBadRequest,
			body: RestError("dev auth: dev ID and auth ID mismatch"),
		},
	}

	for idx := range tcases {
		tc := tcases[idx]
		t.Run(fmt.Sprintf("tc %d", idx), func(t *testing.T) {
			t.Parallel()

			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}

}

func TestApiDevAuthVerifyToken(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := []struct {
		req     *http.Request
		code    int
		body    string
		headers map[string]string
		err     error
	}{
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tokens/verify", nil),
			code: http.StatusUnauthorized,
			body: RestError(ErrNoAuthHeader.Error()),
			err:  nil,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tokens/verify", nil),
			code: 200,
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: nil,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tokens/verify", nil),
			code: http.StatusForbidden,
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: jwt.ErrTokenExpired,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tokens/verify", nil),
			code: http.StatusUnauthorized,
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: jwt.ErrTokenInvalid,
		},
		{
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tokens/verify", nil),
			code: 500,
			body: RestError("internal error"),
			headers: map[string]string{
				"authorization": "dummytoken",
			},
			err: errors.New("some error that will only be logged"),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			da := &mocks.App{}
			da.On("VerifyToken",
				mtest.ContextMatcher(),
				mock.AnythingOfType("string")).
				Return(tc.err)

			apih := makeMockApiHandler(t, da)
			if len(tc.headers) > 0 {
				tc.req.Header.Set("authorization", tc.headers["authorization"])
			}
			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}

}

func TestApiDevAuthDeleteToken(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := []struct {
		req  *http.Request
		code int
		body string
		err  error
	}{
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/tokens/foo", nil),
			code: http.StatusNoContent,
			err:  nil,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/tokens/foo", nil),
			code: http.StatusNotFound,
			err:  store.ErrTokenNotFound,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/tokens/foo", nil),
			code: http.StatusInternalServerError,
			body: RestError("internal error"),
			err:  errors.New("some error that will only be logged"),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			da := &mocks.App{}
			da.On("RevokeToken",
				mtest.ContextMatcher(),
				mock.AnythingOfType("string")).
				Return(tc.err)

			apih := makeMockApiHandler(t, da)
			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}

}

func TestApiGetDevice(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	dev := &model.Device{
		Id:     "foo",
		PubKey: "pubkey",
		Status: model.DevStatusPending,
	}
	tcases := []struct {
		req    *http.Request
		code   int
		body   string
		device *model.Device
		err    error
	}{
		{
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/devauth/devices/foo", nil),
			code:   http.StatusOK,
			device: dev,
			err:    nil,
			body:   string(asJSON(dev)),
		},
		{
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/devauth/devices/bar", nil),
			code: http.StatusNotFound,
			err:  store.ErrDevNotFound,
			body: RestError("device not found"),
		},
	}

	for i := range tcases {
		tc := tcases[i]

		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			da := &mocks.App{}
			da.On("GetDevice",
				mtest.ContextMatcher(),
				mock.AnythingOfType("string")).
				Return(tc.device, tc.err)

			apih := makeMockApiHandler(t, da)
			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}
}

func TestApiGetDevices(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	devs := []model.Device{
		{
			Id:     "foo",
			PubKey: "pubkey",
			Status: model.DevStatusPending,
		},
		{
			Id:     "bar",
			PubKey: "pubkey2",
			Status: model.DevStatusRejected,
		},
		{
			Id:     "baz",
			PubKey: "pubkey3",
			Status: model.DevStatusRejected,
		},
	}

	tcases := []struct {
		req     *http.Request
		code    int
		body    string
		devices []model.Device
		err     error
		skip    uint
		limit   uint
	}{
		{
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/devauth/devices", nil),
			code:    http.StatusOK,
			devices: devs,
			err:     nil,
			skip:    0,
			limit:   rest_utils.PerPageDefault + 1,
			body:    string(asJSON(devs)),
		},
		{
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/devauth/devices", nil),
			code:    http.StatusOK,
			devices: []model.Device{},
			skip:    0,
			limit:   rest_utils.PerPageDefault + 1,
			err:     nil,
			body:    "[]",
		},
		{
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/devauth/devices?page=2&per_page=2", nil),
			devices: devs,
			skip:    2,
			limit:   3,
			code:    http.StatusOK,
			// reqquested 2 devices per page, so expect only 2
			body: string(asJSON(devs[:2])),
		},
		{
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/devauth/devices?page=2&per_page=2", nil),
			skip:  2,
			limit: 3,
			code:  http.StatusInternalServerError,
			err:   errors.New("failed"),
			body:  RestError("internal error"),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %v", i), func(t *testing.T) {
			t.Parallel()

			da := &mocks.App{}
			da.On("GetDevices",
				mtest.ContextMatcher(),
				tc.skip, tc.limit).Return(
				tc.devices, tc.err)

			apih := makeMockApiHandler(t, da)
			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}
}

func asJSON(sth interface{}) []byte {
	data, _ := json.Marshal(sth)
	return data
}

func TestApiDevAuthDecommissionDevice(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := []struct {
		req  *http.Request
		code int
		body string
		err  error
	}{
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/devices/foo", nil),
			code: http.StatusNoContent,
			err:  nil,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/devices/foo", nil),
			code: http.StatusNotFound,
			err:  store.ErrDevNotFound,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/devices/foo", nil),
			code: http.StatusInternalServerError,
			body: RestError("internal error"),
			err:  errors.New("some error that will only be logged"),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			da := &mocks.App{}
			da.On("DecommissionDevice",
				mtest.ContextMatcher(),
				mock.AnythingOfType("string")).
				Return(tc.err)

			apih := makeMockApiHandler(t, da)
			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}
}

func TestApiDevAuthPutTenantLimit(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := []struct {
		req    *http.Request
		code   int
		body   string
		tenant string
		limit  model.Limit
		err    error
	}{
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/internal/v1/devauth/tenant/foo/limits/max_devices",
				map[string]int{
					"limit": 123,
				}),
			limit: model.Limit{
				Name:  model.LimitMaxDeviceCount,
				Value: 123,
			},
			tenant: "foo",
			code:   http.StatusNoContent,
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/internal/v1/devauth/tenant/foo/limits/max_devices",
				[]string{"garbage"}),
			code: http.StatusBadRequest,
			body: RestError("failed to decode limit request: json: cannot unmarshal array into Go value of type http.LimitValue"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/internal/v1/devauth/tenant/foo/limits/bogus-limit",
				map[string]int{
					"limit": 123,
				}),
			code: http.StatusBadRequest,
			body: RestError("unsupported limit bogus-limit"),
		},
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/internal/v1/devauth/tenant/foo/limits/max_devices",
				map[string]int{
					"limit": 123,
				}),
			tenant: "foo",
			limit:  model.Limit{Name: model.LimitMaxDeviceCount, Value: 123},
			code:   http.StatusInternalServerError,
			err:    errors.New("failed"),
			body:   RestError("internal error"),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			da := &mocks.App{}
			da.On("SetTenantLimit",
				mtest.ContextMatcher(),
				tc.tenant,
				tc.limit).
				Return(tc.err)

			apih := makeMockApiHandler(t, da)
			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}
}

func TestApiDevAuthGetLimit(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := []struct {
		limit string

		daLimit *model.Limit
		daErr   error

		code int
		body string
	}{
		{
			limit: "max_devices",

			daLimit: &model.Limit{
				Name:  model.LimitMaxDeviceCount,
				Value: 123,
			},
			daErr: nil,

			code: http.StatusOK,
			body: string(asJSON(
				model.Limit{
					Name:  model.LimitMaxDeviceCount,
					Value: 123,
				},
			)),
		},
		{
			limit: "bogus",

			code: http.StatusBadRequest,
			body: RestError("unsupported limit bogus"),
		},
		{
			limit: "max_devices",

			daLimit: nil,
			daErr:   errors.New("generic error"),

			code: http.StatusInternalServerError,
			body: RestError("internal error"),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			req := test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/devauth/limits/"+tc.limit,
				nil)

			da := &mocks.App{}
			da.On("GetLimit",
				mtest.ContextMatcher(),
				tc.limit).
				Return(tc.daLimit, tc.daErr)

			apih := makeMockApiHandler(t, da)
			runTestRequest(t, apih, req, tc.code, tc.body)
		})
	}
}
