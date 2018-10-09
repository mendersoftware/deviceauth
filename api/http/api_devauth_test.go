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
package http

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/deviceauth/client/tenant"
	"github.com/mendersoftware/deviceauth/devauth"
	"github.com/mendersoftware/deviceauth/devauth/mocks"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	smocks "github.com/mendersoftware/deviceauth/store/mocks"
	mtest "github.com/mendersoftware/deviceauth/utils/testing"
	mt "github.com/mendersoftware/go-lib-micro/testing"
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

func makeMockApiHandler(t *testing.T, da devauth.App, db store.DataStore) http.Handler {
	handlers := NewDevAuthApiHandlers(da, db)
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
					"id_data":      `{"sn":"0001"}`,
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
					"id_data":      `{"sn":"0001"}`,
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
					"id_data":      `{"sn":"0001"}`,
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
					"id_data":      `{"sn":"0001"}`,
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
				},
				privkey,
				"",
				t),
			"",
			devauth.MakeErrDevAuthUnauthorized(
				tenant.MakeErrTokenVerificationFailed(
					errors.New("account suspended"),
				)),
			401,
			RestError("account suspended"),
		},
		{
			//invalid id data (not json)
			makeAuthReq(
				map[string]interface{}{
					"id_data":      `"sn":"0001"`,
					"pubkey":       pubkeyStr,
					"tenant_token": "tenant-0001",
				},
				privkey,
				"",
				t),
			"",
			nil,
			400,
			RestError("invalid auth request: invalid character ':' after top-level value"),
		},
		{
			//complete body + signature, auth ok
			makeAuthReq(
				map[string]interface{}{
					"id_data":      `{"sn":"0001"}`,
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
					"id_data": `{"sn":"0001"}`,
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
		{
			//complete body, invalid public key
			makeAuthReq(
				map[string]interface{}{
					"id_data":      `{"sn":"0001"}`,
					"pubkey":       "invalid",
					"tenant_token": "tenant-0001",
				},
				privkey,
				"",
				t),
			"dummytoken",
			nil,
			400,
			RestError("invalid auth request: cannot decode public key"),
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

			apih := makeMockApiHandler(t, da, nil)

			recorded := runTestRequest(t, apih, tc.req, tc.code, tc.body)
			if tc.code == http.StatusOK {
				assert.Equal(t, "application/jwt",
					recorded.Recorder.HeaderMap.Get("Content-Type"))
			}
		})
	}
}

func TestApiDevAuthPreauthDevice(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	pubkeyStr := mtest.LoadPubKeyStr("testdata/public.pem", t)

	testCases := map[string]struct {
		body interface{}

		devAuthErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				DeviceId:  "device-id",
				IdData:    `{"sn":"0001"}`,
				PubKey:    pubkeyStr,
			},
			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil),
		},
		"invalid: id data is not json": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				DeviceId:  "device-id",
				IdData:    `"sn":"0001"`,
				PubKey:    pubkeyStr,
			},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode preauth request: invalid character ':' after top-level value")),
		},
		"invalid: no auth set id": {
			body: &model.PreAuthReq{
				DeviceId: "device-id",
				IdData:   `{"sn":"0001"}`,
				PubKey:   pubkeyStr,
			},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode preauth request: auth_set_id: non zero value required;")),
		},
		"invalid: no device_id": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				IdData:    `{"sn":"0001"}`,
				PubKey:    pubkeyStr,
			},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode preauth request: device_id: non zero value required;")),
		},
		"invalid: no id data": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				DeviceId:  "device-id",
				PubKey:    pubkeyStr,
			},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode preauth request: id_data: non zero value required;")),
		},
		"invalid: no pubkey": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				DeviceId:  "device-id",
				IdData:    `{"sn":"0001"}`,
			},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode preauth request: pubkey: non zero value required;")),
		},
		"invalid: no body": {
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode preauth request: EOF")),
		},
		"invalid public key": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				DeviceId:  "device-id",
				IdData:    `{"sn":"0001"}`,
				PubKey:    "invalid",
			},
			devAuthErr: devauth.ErrDeviceExists,
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode preauth request: cannot decode public key")),
		},
		"devauth: device exists": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				DeviceId:  "device-id",
				IdData:    `{"sn":"0001"}`,
				PubKey:    pubkeyStr,
			},
			devAuthErr: devauth.ErrDeviceExists,
			checker: mt.NewJSONResponse(
				http.StatusConflict,
				nil,
				restError("device already exists")),
		},
		"devauth: generic error": {
			body: &model.PreAuthReq{
				AuthSetId: "auth-set-id",
				DeviceId:  "device-id",
				IdData:    `{"sn":"0001"}`,
				PubKey:    pubkeyStr,
			},
			devAuthErr: errors.New("generic"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {
			da := &mocks.App{}
			da.On("PreauthorizeDevice",
				mtest.ContextMatcher(),
				tc.body).
				Return(tc.devAuthErr)

			apih := makeMockApiHandler(t, da, nil)

			//make request
			req := makeReq("POST",
				"http://1.2.3.4/api/management/v1/devauth/devices",
				"",
				tc.body)

			recorded := test.RunRequest(t, apih, req)
			mt.CheckResponse(t, tc.checker, recorded)
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
		"567,890": {
			dev: &model.Device{
				Id:     "foo",
				PubKey: "foobar",
				Status: "pending",
				IdData: "deadcafe",
			},
			err: devauth.ErrMaxDeviceCountReached,
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

	apih := makeMockApiHandler(t, da, nil)
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
		{
			req: test.MakeSimpleRequest("PUT",
				"http://1.2.3.4/api/management/v1/devauth/devices/567/auth/890/status",
				accstatus),
			code: http.StatusUnprocessableEntity,
			body: RestError("maximum number of accepted devices reached"),
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

func TestApiDevAuthDevAdmUpdateAuthSetStatus(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := map[string]struct {
		status interface{}
		aid    string

		dbGetAuthSetRes *model.AuthSet
		dbGetAuthSetErr error

		appAcceptRejectErr error

		code int
		body string
	}{
		"ok": {
			status:          &model.Status{Status: model.DevStatusAccepted},
			aid:             "foo",
			dbGetAuthSetRes: &model.AuthSet{Id: "foo", DeviceId: "bar"},
			body:            string(asJSON(&model.Status{Status: "accepted"})),
			code:            http.StatusOK,
		},
		"ok 2": {
			status:          &model.Status{Status: model.DevStatusRejected},
			aid:             "foo",
			dbGetAuthSetRes: &model.AuthSet{Id: "foo", DeviceId: "bar"},
			body:            string(asJSON(&model.Status{Status: "rejected"})),
			code:            http.StatusOK,
		},
		"error: empty payload": {
			status: nil,
			code:   http.StatusBadRequest,
			body:   RestError("failed to decode status data: JSON payload is empty"),
		},
		"error: invalid status": {
			status: &model.Status{Status: "foo"},
			code:   http.StatusBadRequest,
			body:   RestError("incorrect device status"),
		},
		"error: get auth set: not found": {
			status: &model.Status{Status: model.DevStatusAccepted},

			aid:             "foo",
			dbGetAuthSetErr: store.ErrDevNotFound,

			body: RestError("authorization set not found"),
			code: http.StatusNotFound,
		},
		"error: get auth set: generic": {
			status: &model.Status{Status: model.DevStatusRejected},

			aid:             "foo",
			dbGetAuthSetErr: errors.New("some internal error"),

			body: RestError("internal error"),
			code: http.StatusInternalServerError,
		},
		"error: accept: not found": {
			status: &model.Status{Status: model.DevStatusAccepted},

			aid:                "foo",
			dbGetAuthSetRes:    &model.AuthSet{Id: "foo", DeviceId: "dev-foo"},
			appAcceptRejectErr: store.ErrDevNotFound,

			body: RestError("authorization set not found"),
			code: http.StatusNotFound,
		},
		"error: accept: max devices": {
			status: &model.Status{Status: model.DevStatusAccepted},

			aid:                "foo",
			dbGetAuthSetRes:    &model.AuthSet{Id: "foo", DeviceId: "dev-foo"},
			appAcceptRejectErr: devauth.ErrMaxDeviceCountReached,

			body: RestError("maximum number of accepted devices reached"),
			code: http.StatusUnprocessableEntity,
		},
		"error: accept: generic": {
			status: &model.Status{Status: model.DevStatusAccepted},

			aid:                "foo",
			dbGetAuthSetRes:    &model.AuthSet{Id: "foo", DeviceId: "dev-foo"},
			appAcceptRejectErr: errors.New("some internal error"),

			body: RestError("internal error"),
			code: http.StatusInternalServerError,
		},
		"error: reject: not found": {
			status: &model.Status{Status: model.DevStatusRejected},

			aid:                "foo",
			dbGetAuthSetRes:    &model.AuthSet{Id: "foo", DeviceId: "dev-foo"},
			appAcceptRejectErr: store.ErrDevNotFound,

			body: RestError("authorization set not found"),
			code: http.StatusNotFound,
		},
		"error: reject: generic": {
			status: &model.Status{Status: model.DevStatusRejected},

			aid:                "foo",
			dbGetAuthSetRes:    &model.AuthSet{Id: "foo", DeviceId: "dev-foo"},
			appAcceptRejectErr: errors.New("some internal error"),

			body: RestError("internal error"),
			code: http.StatusInternalServerError,
		},
	}

	for idx := range tcases {
		tc := tcases[idx]
		t.Run(fmt.Sprintf("tc %s", idx), func(t *testing.T) {
			t.Parallel()

			req := test.MakeSimpleRequest("PUT",
				fmt.Sprintf("http://1.2.3.4/api/management/v1/admission/devices/%s/status", tc.aid),
				tc.status)

			da := &mocks.App{}
			da.On("AcceptDeviceAuth",
				mtest.ContextMatcher(),
				mock.AnythingOfType("string"),
				tc.aid).Return(tc.appAcceptRejectErr)
			da.On("RejectDeviceAuth",
				mtest.ContextMatcher(),
				mock.AnythingOfType("string"),
				tc.aid).Return(tc.appAcceptRejectErr)

			db := &smocks.DataStore{}
			db.On("GetAuthSetById",
				mtest.ContextMatcher(),
				tc.aid).Return(tc.dbGetAuthSetRes, tc.dbGetAuthSetErr)

			apih := makeMockApiHandler(t, da, db)

			runTestRequest(t, apih, req, tc.code, tc.body)
		})
	}
}

func TestApiDevAuthDevAdmGetDeviceStatus(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := map[string]struct {
		aid string

		dbAuthSet *model.AuthSet
		dbErr     error

		checker mt.ResponseChecker
	}{
		"ok": {
			aid: "foo",

			dbAuthSet: &model.AuthSet{Status: "accepted"},

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				model.Status{Status: "accepted"}),
		},
		"error: not found": {
			aid: "foo",

			dbErr: store.ErrDevNotFound,

			checker: mt.NewJSONResponse(
				http.StatusNotFound,
				nil,
				restError("authorization set not found")),
		},
		"error: generic": {
			aid: "foo",

			dbErr: errors.New("generic error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %s", i), func(t *testing.T) {
			t.Parallel()

			req := makeReq("GET",
				fmt.Sprintf("http://1.2.3.4/api/management/v1/admission/devices/%s/status", tc.aid),
				"", nil)

			db := &smocks.DataStore{}
			db.On("GetAuthSetById",
				mtest.ContextMatcher(),
				tc.aid).Return(tc.dbAuthSet, tc.dbErr)

			apih := makeMockApiHandler(t, nil, db)

			recorded := test.RunRequest(t, apih, req)
			mt.CheckResponse(t, tc.checker, recorded)
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

			apih := makeMockApiHandler(t, da, nil)
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

			apih := makeMockApiHandler(t, da, nil)
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

			apih := makeMockApiHandler(t, da, nil)
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

			apih := makeMockApiHandler(t, da, nil)
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

			apih := makeMockApiHandler(t, da, nil)
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

			apih := makeMockApiHandler(t, da, nil)
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
				LimitValue{
					Limit: 123,
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

			apih := makeMockApiHandler(t, da, nil)
			runTestRequest(t, apih, req, tc.code, tc.body)
		})
	}
}

func TestApiDevAuthGetTenantLimit(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := []struct {
		limit    string
		tenantId string

		daLimit *model.Limit
		daErr   error

		code int
		body string
	}{
		{
			limit:    "max_devices",
			tenantId: "tenant-foo",

			daLimit: &model.Limit{
				Name:  model.LimitMaxDeviceCount,
				Value: 123,
			},
			daErr: nil,

			code: http.StatusOK,
			body: string(asJSON(
				LimitValue{
					Limit: 123,
				},
			)),
		},
		{
			limit:    "bogus",
			tenantId: "tenant-foo",

			code: http.StatusBadRequest,
			body: RestError("unsupported limit bogus"),
		},
		{
			limit:    "max_devices",
			tenantId: "tenant-foo",

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
				"http://1.2.3.4/api/internal/v1/devauth/tenant/"+
					tc.tenantId+
					"/limits/"+
					tc.limit,

				nil)

			da := &mocks.App{}
			da.On("GetTenantLimit",
				mtest.ContextMatcher(),
				tc.limit,
				tc.tenantId).
				Return(tc.daLimit, tc.daErr)

			apih := makeMockApiHandler(t, da, nil)
			runTestRequest(t, apih, req, tc.code, tc.body)
		})
	}
}

func TestApiDevAuthGetDevicesCount(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := []struct {
		req    *http.Request
		status string

		daCnt int
		daErr error

		code int
		body string
	}{
		{
			status: "pending",

			daCnt: 5,
			daErr: nil,

			code: http.StatusOK,
			body: string(asJSON(
				model.Count{
					Count: 5,
				},
			)),
		},
		{
			status: "accepted",

			daCnt: 0,
			daErr: nil,

			code: http.StatusOK,
			body: string(asJSON(
				model.Count{
					Count: 0,
				},
			)),
		},
		{
			status: "rejected",

			daCnt: 4,
			daErr: nil,

			code: http.StatusOK,
			body: string(asJSON(
				model.Count{
					Count: 4,
				},
			)),
		},
		{
			status: model.DevStatusPreauth,

			daCnt: 7,
			daErr: nil,

			code: http.StatusOK,
			body: string(asJSON(
				model.Count{
					Count: 7,
				},
			)),
		},
		{
			status: "",

			daCnt: 10,
			daErr: nil,

			code: http.StatusOK,
			body: string(asJSON(
				model.Count{
					Count: 10,
				},
			)),
		},
		{
			status: "bogus",

			code: http.StatusBadRequest,
			body: RestError("status must be one of: pending, accepted, rejected, preauthorized"),
		},
		{
			status: "accepted",

			daErr: errors.New("generic error"),

			code: http.StatusInternalServerError,
			body: RestError("internal error"),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			url := "http://1.2.3.4/api/management/v1/devauth/devices/count"
			if tc.status != "" {
				url += "?status=" + tc.status
			}

			req := test.MakeSimpleRequest("GET", url, nil)

			da := &mocks.App{}
			da.On("GetDevCountByStatus",
				mtest.ContextMatcher(),
				tc.status).
				Return(tc.daCnt, tc.daErr)

			apih := makeMockApiHandler(t, da, nil)
			runTestRequest(t, apih, req, tc.code, tc.body)
		})
	}
}

func TestApiDevAuthPostTenants(t *testing.T) {
	testCases := map[string]struct {
		req        *http.Request
		devAuthErr error
		respCode   int
		respBody   string
	}{
		"ok": {
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tenants",
				model.NewTenant{TenantId: "foo"}),
			respCode: 201,
			respBody: "",
		},
		"error: empty request": {
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tenants",
				nil),
			respCode: 400,
			respBody: RestError("EOF"),
		},
		"error: no tenant_id": {
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tenants",
				model.NewTenant{TenantId: ""},
			),
			respCode: 400,
			respBody: RestError("tenant_id must be provided"),
		},
		"error: generic": {
			req: test.MakeSimpleRequest("POST",
				"http://1.2.3.4/api/internal/v1/devauth/tenants",
				model.NewTenant{TenantId: "foo"},
			),
			devAuthErr: errors.New("can't provision tenant"),
			respCode:   500,
			respBody:   RestError("internal error"),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)
		da := &mocks.App{}

		da.On("ProvisionTenant",
			mock.MatchedBy(func(c context.Context) bool { return true }),
			mock.AnythingOfType("string")).Return(tc.devAuthErr)

		apih := makeMockApiHandler(t, da, nil)

		rest.ErrorFieldName = "error"

		runTestRequest(t, apih, tc.req, tc.respCode, tc.respBody)
	}
}

func makeReq(method, url, auth string, body interface{}) *http.Request {
	req := test.MakeSimpleRequest(method, url, body)

	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Add(requestid.RequestIdHeader, "test")

	return req
}

func restError(status string) map[string]interface{} {
	return map[string]interface{}{"error": status, "request_id": "test"}
}

func TestApiDevAuthDeleteDeviceAuthSet(t *testing.T) {
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
				"http://1.2.3.4/api/management/v1/devauth/devices/foo/auth/bar", nil),
			code: http.StatusNoContent,
			err:  nil,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/devices/foo/auth/bar", nil),
			code: http.StatusInternalServerError,
			body: RestError("internal error"),
			err:  store.ErrAuthSetNotFound,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/devices/foo/auth/bar", nil),
			code: http.StatusNotFound,
			err:  store.ErrDevNotFound,
		},
		{
			req: test.MakeSimpleRequest("DELETE",
				"http://1.2.3.4/api/management/v1/devauth/devices/foo/auth/bar", nil),
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
			da.On("DeleteAuthSet",
				mtest.ContextMatcher(),
				"foo",
				"bar").
				Return(tc.err)

			apih := makeMockApiHandler(t, da, nil)
			runTestRequest(t, apih, tc.req, tc.code, tc.body)
		})
	}
}

func TestApiDeleteTokens(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := map[string]struct {
		tenantId string
		deviceId string

		devAuthErr error

		checker mt.ResponseChecker
	}{
		"ok, all tokens": {
			tenantId: "foo",
			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil),
		},
		"ok, device's tokens": {
			tenantId: "foo",
			deviceId: "dev-foo",
			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil),
		},
		"error, no tenant id": {
			deviceId: "dev-foo",
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("tenant_id must be provided")),
		},
		"error, devauth": {
			tenantId:   "foo",
			devAuthErr: errors.New("generic error"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
	}

	for n := range tcases {
		tc := tcases[n]
		t.Run(fmt.Sprintf("tc %s", n), func(t *testing.T) {
			t.Parallel()

			da := &mocks.App{}
			da.On("DeleteTokens",
				mtest.ContextMatcher(),
				tc.tenantId,
				tc.deviceId).
				Return(tc.devAuthErr)

			//make request
			url := fmt.Sprintf("http://1.2.3.4/api/internal/v1/devauth/tokens?tenant_id=%v&device_id=%v",
				tc.tenantId,
				tc.deviceId)

			req := makeReq("DELETE",
				url,
				"",
				nil)

			apih := makeMockApiHandler(t, da, nil)

			recorded := test.RunRequest(t, apih, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestApiDevAuthGetTenantDeviceStatus(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := map[string]struct {
		tid string
		did string

		daStatus *model.Status
		daErr    error

		checker mt.ResponseChecker
	}{
		"ok": {
			tid: "foo",
			did: "bar",

			daStatus: &model.Status{Status: "accepted"},

			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				model.Status{Status: "accepted"}),
		},
		"error: tenant id empty": {
			did: "bar",

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("tenant id (tid) cannot be empty")),
		},
		"error: device id empty": {
			tid: "foo",

			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("device id (did) cannot be empty")),
		},
		"error: not found": {
			tid: "foo",
			did: "bar",

			daErr: devauth.ErrDeviceNotFound,

			checker: mt.NewJSONResponse(
				http.StatusNotFound,
				nil,
				restError("device not found")),
		},
		"error: generic": {
			tid: "foo",
			did: "bar",

			daErr: errors.New("generic error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
	}

	for i := range tcases {
		tc := tcases[i]
		t.Run(fmt.Sprintf("tc %s", i), func(t *testing.T) {
			t.Parallel()

			req := makeReq("GET",
				fmt.Sprintf("http://1.2.3.4/api/internal/v1/devauth/tenants/%s/devices/%s/status", tc.tid, tc.did),
				"",
				nil)

			da := &mocks.App{}
			da.On("GetTenantDeviceStatus",
				mtest.ContextMatcher(),
				tc.tid,
				tc.did,
			).Return(tc.daStatus, tc.daErr)

			apih := makeMockApiHandler(t, da, nil)

			recorded := test.RunRequest(t, apih, req)
			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestApiDevAuthDevAdmGetDevices(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := map[string]struct {
		skip   int
		limit  int
		filter store.AuthSetFilter

		getAuthSetsRes []model.DevAdmAuthSet
		getAuthSetsErr error

		req *http.Request

		code  int
		body  string
		links []string
	}{
		"valid pagination, no next page": {
			skip:  15,
			limit: 6,

			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=4&per_page=5", nil),

			getAuthSetsRes: mockAuthSets(5),

			code: 200,
			body: toJsonString(t, mockAuthSets(5)),
			links: []string{
				`<http://1.2.3.4/api/management/v1/admission/devices?page=3&per_page=5>; rel="prev"`,
				`<http://1.2.3.4/api/management/v1/admission/devices?page=1&per_page=5>; rel="first"`,
			},
		},

		"valid pagination, with next page": {
			skip:  15,
			limit: 6,

			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=4&per_page=5", nil),

			getAuthSetsRes: mockAuthSets(9),

			code: 200,
			body: toJsonString(t, mockAuthSets(5)),
			links: []string{
				`<http://1.2.3.4/api/management/v1/admission/devices?page=3&per_page=5>; rel="prev"`,
				`<http://1.2.3.4/api/management/v1/admission/devices?page=1&per_page=5>; rel="first"`,
			},
		},
		"invalid pagination: format": {
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=foo&per_page=5", nil),
			code: 400,
			body: RestError(rest_utils.MsgQueryParmInvalid("page")),
		},
		"invalid pagination: bounds": {
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=0&per_page=5", nil),
			code: 400,
			body: RestError(rest_utils.MsgQueryParmLimit("page")),
		},
		"valid status: accepted": {
			skip:   15,
			limit:  6,
			filter: store.AuthSetFilter{Status: "accepted"},

			getAuthSetsRes: mockAuthSets(6),
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=4&per_page=5&status=accepted", nil),
			code: 200,
			body: toJsonString(t, mockAuthSets(5)),
		},
		"valid status: preauthorized": {
			skip:   15,
			limit:  6,
			filter: store.AuthSetFilter{Status: "preauthorized"},

			getAuthSetsRes: mockAuthSets(6),
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=4&per_page=5&status=preauthorized", nil),
			code: 200,
			body: toJsonString(t, mockAuthSets(5)),
		},
		"invalid status": {
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=1&per_page=5&status=foo", nil),
			code: 400,
			body: RestError(rest_utils.MsgQueryParmOneOf("status", DevStatuses)),
		},
		"db.GetAuthSets error": {
			skip:           15,
			limit:          6,
			getAuthSetsErr: errors.New("db error"),
			req: test.MakeSimpleRequest("GET",
				"http://1.2.3.4/api/management/v1/admission/devices?page=4&per_page=5", nil),
			code: 500,
			body: RestError("internal error"),
		},
	}

	for idx := range tcases {
		tc := tcases[idx]
		t.Run(fmt.Sprintf("tc %s", idx), func(t *testing.T) {
			t.Parallel()

			db := &smocks.DataStore{}
			db.On("GetAuthSets",
				mtest.ContextMatcher(),
				tc.skip,
				tc.limit,
				tc.filter).Return(tc.getAuthSetsRes, tc.getAuthSetsErr)

			apih := makeMockApiHandler(t, nil, db)

			recorded := runTestRequest(t, apih, tc.req, tc.code, tc.body)

			for _, h := range tc.links {
				assert.Equal(t, h, ExtractHeader("Link", h, recorded))
			}
		})
	}
}

func TestApiDevAuthDevAdmGetDevice(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := map[string]struct {
		aid string

		dbAuthSet *model.AuthSet
		dbErr     error

		checker mt.ResponseChecker
	}{
		"ok": {
			aid: "foo",

			dbAuthSet: &model.AuthSet{
				Id:       "foo",
				DeviceId: "foo-dev",
				IdData:   `{"sn": "dev-foo-sn"}`,
				Status:   "accepted",
				PubKey:   "foo-dev-key",
			},
			checker: mt.NewJSONResponse(
				http.StatusOK,
				nil,
				&model.DevAdmAuthSet{
					Id:             "foo",
					DeviceId:       "foo-dev",
					DeviceIdentity: `{"sn": "dev-foo-sn"}`,
					Status:         "accepted",
					Key:            "foo-dev-key",
					Attributes: map[string]interface{}{
						"sn": "dev-foo-sn",
					}}),
		},
		"error: not found": {
			aid: "foo",

			dbErr: store.ErrDevNotFound,
			checker: mt.NewJSONResponse(
				http.StatusNotFound,
				nil,
				restError("authorization set not found")),
		},
		"error: generic db error": {
			aid: "foo",

			dbErr: errors.New("an error"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
		"error: auth set conversion error": {
			aid: "foo",

			dbAuthSet: &model.AuthSet{
				Id:       "foo",
				DeviceId: "foo-dev",
				IdData:   "not json",
				Status:   "accepted",
				PubKey:   "foo-dev-key",
			},
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
	}

	for idx := range tcases {
		tc := tcases[idx]
		t.Run(fmt.Sprintf("tc %s", idx), func(t *testing.T) {
			t.Parallel()

			db := &smocks.DataStore{}
			db.On("GetAuthSetById",
				mtest.ContextMatcher(),
				tc.aid).Return(tc.dbAuthSet, tc.dbErr)

			apih := makeMockApiHandler(t, nil, db)

			//make request
			req := makeReq("GET",
				"http://1.2.3.4/api/management/v1/admission/devices/"+tc.aid,
				"",
				nil)
			recorded := test.RunRequest(t, apih, req)

			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func TestApiDevAuthDevAdmDeleteDeviceAuthSet(t *testing.T) {
	t.Parallel()

	// enforce specific field naming in errors returned by API
	updateRestErrorFieldName()

	tcases := map[string]struct {
		aid string

		dbAuthSet *model.AuthSet
		dbErr     error

		daErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			aid: "foo",

			dbAuthSet: &model.AuthSet{
				Id:       "foo",
				DeviceId: "foo-dev",
				IdData:   `{"sn": "dev-foo-sn"}`,
				Status:   "accepted",
				PubKey:   "foo-dev-key",
			},

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil),
		},
		"error: not found (db)": {
			aid: "foo",

			dbErr: store.ErrDevNotFound,

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil),
		},

		"error: not found(app)": {
			aid: "foo",

			dbAuthSet: &model.AuthSet{
				Id:       "foo",
				DeviceId: "foo-dev",
				IdData:   `{"sn": "dev-foo-sn"}`,
				Status:   "accepted",
				PubKey:   "foo-dev-key",
			},

			daErr: store.ErrDevNotFound,

			checker: mt.NewJSONResponse(
				http.StatusNoContent,
				nil,
				nil),
		},
		"error: generic db error": {
			aid: "foo",

			dbErr: errors.New("an error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
		"error: generic app error": {
			aid: "foo",

			dbAuthSet: &model.AuthSet{
				Id:       "foo",
				DeviceId: "foo-dev",
				IdData:   `{"sn": "dev-foo-sn"}`,
				Status:   "accepted",
				PubKey:   "foo-dev-key",
			},

			daErr: errors.New("an error"),

			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
	}

	for idx := range tcases {
		tc := tcases[idx]
		t.Run(fmt.Sprintf("tc %s", idx), func(t *testing.T) {
			t.Parallel()

			db := &smocks.DataStore{}
			db.On("GetAuthSetById",
				mtest.ContextMatcher(),
				tc.aid).Return(tc.dbAuthSet, tc.dbErr)

			da := &mocks.App{}
			if tc.dbAuthSet != nil {
				da.On("DeleteAuthSet",
					mtest.ContextMatcher(),
					tc.dbAuthSet.DeviceId,
					tc.aid).Return(tc.daErr)
			} else {
				da.On("DeleteAuthSet",
					mtest.ContextMatcher(),
					mock.AnythingOfType("string"),
					tc.aid).Return(tc.daErr)
			}

			apih := makeMockApiHandler(t, da, db)

			//make request
			req := makeReq("DELETE",
				"http://1.2.3.4/api/management/v1/admission/devices/"+tc.aid,
				"",
				nil)
			recorded := test.RunRequest(t, apih, req)

			mt.CheckResponse(t, tc.checker, recorded)
		})
	}
}

func mockAuthSets(num int) []model.DevAdmAuthSet {
	var sets []model.DevAdmAuthSet
	for i := 0; i < num; i++ {
		sets = append(sets, model.DevAdmAuthSet{
			Id:       strconv.Itoa(i),
			DeviceId: strconv.Itoa(i),
		})
	}
	return sets
}

func ExtractHeader(hdr, val string, r *test.Recorded) string {
	rec := r.Recorder
	for _, v := range rec.Header()[hdr] {
		if v == val {
			return v
		}
	}

	return ""
}

func TestApiDevAuthDevAdmPostDeviceAuth(t *testing.T) {
	validKey := `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzogVU7RGDilbsoUt/DdH
VJvcepl0A5+xzGQ50cq1VE/Dyyy8Zp0jzRXCnnu9nu395mAFSZGotZVr+sWEpO3c
yC3VmXdBZmXmQdZqbdD/GuixJOYfqta2ytbIUPRXFN7/I7sgzxnXWBYXYmObYvdP
okP0mQanY+WKxp7Q16pt1RoqoAd0kmV39g13rFl35muSHbSBoAW3GBF3gO+mF5Ty
1ddp/XcgLOsmvNNjY+2HOD5F/RX0fs07mWnbD7x+xz7KEKjF+H7ZpkqCwmwCXaf0
iyYyh1852rti3Afw4mDxuVSD7sd9ggvYMc0QHIpQNkD4YWOhNiE1AB0zH57VbUYG
UwIDAQAB
-----END PUBLIC KEY-----`

	testCases := map[string]struct {
		body interface{}

		devAuthErr error

		checker mt.ResponseChecker
	}{
		"ok": {
			body: &model.DevAdmAuthSetReq{Key: validKey, DeviceId: toJsonString(t,
				map[string]string{
					"mac": "00:00:00:01",
				}),
			},
			checker: mt.NewJSONResponse(
				http.StatusCreated,
				nil,
				nil),
		},
		"error, invalid key": {
			body: &model.DevAdmAuthSetReq{Key: "foo", DeviceId: toJsonString(t,
				map[string]string{
					"mac": "00:00:00:01",
				}),
			},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("cannot decode public key")),
		},
		"error: empty request": {
			body: nil,
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("EOF")),
		},
		"error: generic": {
			body: &model.DevAdmAuthSetReq{Key: validKey, DeviceId: toJsonString(t,
				map[string]string{
					"mac": "00:00:00:01",
				})},
			devAuthErr: errors.New("generic error"),
			checker: mt.NewJSONResponse(
				http.StatusInternalServerError,
				nil,
				restError("internal error")),
		},
		"error: no key": {
			body: &model.DevAdmAuthSetReq{Key: "", DeviceId: toJsonString(t,
				map[string]string{
					"mac": "00:00:00:01",
				})},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("key: non zero value required;")),
		},
		"error: no identity data": {
			body: &model.DevAdmAuthSetReq{Key: validKey},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("device_identity: non zero value required;")),
		},
		"error: invalid id data": {
			body: &model.DevAdmAuthSetReq{Key: validKey, DeviceId: "{mac: 1234}"},
			checker: mt.NewJSONResponse(
				http.StatusBadRequest,
				nil,
				restError("failed to decode attributes data: invalid character 'm' looking for beginning of object key string")),
		},
		"error: conflict": {
			body: &model.DevAdmAuthSetReq{Key: validKey, DeviceId: toJsonString(t,
				map[string]string{
					"mac": "00:00:00:01",
				})},
			devAuthErr: devauth.ErrDeviceExists,
			checker: mt.NewJSONResponse(
				http.StatusConflict,
				nil,
				restError("device already exists")),
		},
	}

	for name, tc := range testCases {
		t.Logf("test case: %s", name)
		da := &mocks.App{}
		da.On("PreauthorizeDevice",
			mtest.ContextMatcher(),
			mock.AnythingOfType("*model.PreAuthReq")).
			Return(tc.devAuthErr)

		apih := makeMockApiHandler(t, da, nil)

		//make request
		req := makeReq("POST",
			"http://1.2.3.4/api/management/v1/admission/devices",
			"",
			tc.body)

		recorded := test.RunRequest(t, apih, req)
		mt.CheckResponse(t, tc.checker, recorded)
	}
}

func toJsonString(t *testing.T, d interface{}) string {
	out, err := json.Marshal(d)
	if err != nil {
		t.FailNow()
	}

	return string(out)
}
