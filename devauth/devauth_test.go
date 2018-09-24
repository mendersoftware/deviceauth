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
package devauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/globalsign/mgo/bson"
	ctxhttpheader "github.com/mendersoftware/go-lib-micro/context/httpheader"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/deviceauth/client/orchestrator"
	morchestrator "github.com/mendersoftware/deviceauth/client/orchestrator/mocks"
	mtenant "github.com/mendersoftware/deviceauth/client/tenant/mocks"
	"github.com/mendersoftware/deviceauth/jwt"
	mjwt "github.com/mendersoftware/deviceauth/jwt/mocks"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	mstore "github.com/mendersoftware/deviceauth/store/mocks"
	mtesting "github.com/mendersoftware/deviceauth/utils/testing"
)

func TestDevAuthSubmitAuthRequest(t *testing.T) {
	t.Parallel()

	pubKey := "dummy_pubkey"
	idData := "dummy_iddata"
	devId := "dummy_devid"
	authId := "dummy_aid"

	req := model.AuthReq{
		IdData:      idData,
		TenantToken: "tenant",
		PubKey:      pubKey,
	}

	testCases := []struct {
		desc string

		inReq model.AuthReq

		devStatus string

		// key of returned device
		getDevByIdKey string
		getDevByIdErr error

		//id of returned device
		getDevByKeyId string
		getAuthSetErr error

		addDeviceErr  error
		addAuthSetErr error

		devAdmErr error

		tenantVerify          bool
		tenantVerificationErr error

		res string
		err error
	}{
		{
			// pretend we failed to add device to DB
			desc: "db add fail",

			inReq:        req,
			addDeviceErr: errors.New("failed"),
			err:          errors.New("failed"),
		},
		{
			//existing device, existing auth set, auth set accepted,
			//so we should get a token right away
			desc: "known, accepted, give out token",

			inReq: req,

			addDeviceErr:  store.ErrObjectExists,
			addAuthSetErr: store.ErrObjectExists,

			devStatus:     model.DevStatusAccepted,
			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			res: "dummytoken",
		},
		{
			//existing device, existing auth set, auth set rejected,
			//no token
			desc: "known, rejected",

			inReq: req,

			addDeviceErr:  store.ErrObjectExists,
			addAuthSetErr: store.ErrObjectExists,

			devStatus:     model.DevStatusRejected,
			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			err: ErrDevAuthUnauthorized,
		},
		{
			//existing, pending device
			desc: "known, pending",

			inReq: req,

			addDeviceErr:  store.ErrObjectExists,
			addAuthSetErr: store.ErrObjectExists,

			devStatus:     model.DevStatusPending,
			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			err: ErrDevAuthUnauthorized,
		},
		{
			//new device
			desc: "new device",

			inReq: req,

			devStatus: model.DevStatusPending,

			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			err: ErrDevAuthUnauthorized,
		},
		{
			//known device, adding returns that device exists, but
			//trying to fetch it fails
			desc: "known, device fetch data fail",

			inReq: req,

			addDeviceErr: store.ErrObjectExists,

			getDevByIdErr: store.ErrDevNotFound,

			err: errors.New("failed to locate device"),
		},
		{
			//known device and auth set, but fetching auth set fails
			desc: "known, auth set fetch fail",

			inReq: req,

			addDeviceErr:  store.ErrObjectExists,
			addAuthSetErr: store.ErrObjectExists,

			getAuthSetErr: store.ErrDevNotFound,

			err: errors.New("failed to locate device auth set"),
		},
		{
			//new device - tenant token verification failed
			desc: "new device, tenant token verification fail",

			inReq: req,

			err: errors.New("dev auth: unauthorized: token verification failed: account suspended"),

			tenantVerify:          true,
			tenantVerificationErr: errors.New("token verification failed: account suspended"),
		},
		{
			//new device - tenant token verification failed because of other reasons
			desc: "new device, tenant token other fail",

			inReq: req,

			err: errors.New("request to verify tenant token failed"),

			tenantVerify:          true,
			tenantVerificationErr: errors.New("something something failed"),
		},
		{
			//new device - tenant token required but not provided
			desc: "new device, missing but required tenant token",

			inReq: model.AuthReq{
				IdData:      idData,
				TenantToken: "",
				PubKey:      pubKey,
			},

			err: ErrDevAuthUnauthorized,

			tenantVerify:          true,
			tenantVerificationErr: errors.New("should not be called"),
		},
		{
			//new device - tenant token is malformed, but was somehow verified ok
			desc: "new device, malformed tenant token",

			inReq: model.AuthReq{
				IdData:      idData,
				TenantToken: "tenant-foo",
				PubKey:      pubKey,
			},

			err: ErrDevAuthUnauthorized,

			tenantVerify: true,
		},
		{
			// a known device with a correct tenant token
			desc: "known, correct tenant token",

			inReq: model.AuthReq{
				IdData: idData,
				// token with the following claims:
				//   {
				//      "sub": "bogusdevice",
				//      "mender.tenant": "foobar"
				//   }
				TenantToken: "fake.eyJzdWIiOiJib2d1c2RldmljZSIsIm1lbmRlci50ZW5hbnQiOiJmb29iYXIifQ.fake",
				PubKey:      pubKey,
			},

			addDeviceErr:  store.ErrObjectExists,
			addAuthSetErr: store.ErrObjectExists,

			tenantVerify: true,
			err:          ErrDevAuthUnauthorized,
		},
		{
			// a known device of with a correct tenant token, hand
			// out a token with tenant claim in it
			desc: "known, accepted, tenant, give out token with tenant claim",

			inReq: model.AuthReq{
				IdData: idData,
				// token with the following claims:
				//   {
				//      "sub": "bogusdevice",
				//      "mender.tenant": "foobar"
				//   }
				TenantToken: "fake.eyJzdWIiOiJib2d1c2RldmljZSIsIm1lbmRlci50ZW5hbnQiOiJmb29iYXIifQ.fake",
				PubKey:      pubKey,
			},

			addDeviceErr:  store.ErrObjectExists,
			addAuthSetErr: store.ErrObjectExists,

			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			tenantVerify: true,

			devStatus: model.DevStatusAccepted,

			res: "dummytoken",
		},
	}

	for tcidx := range testCases {
		tc := testCases[tcidx]
		t.Run(fmt.Sprintf("tc: %s", tc.desc), func(t *testing.T) {
			t.Parallel()

			// match context in mocks
			ctxMatcher := mtesting.ContextMatcher()

			if tc.tenantVerify {
				// context must carry identity information if
				// tenant verification is enabled, also it must
				// be set up with http Authorization header to
				// use in outgoing requests (via
				// go-lib-micro/context/httpheader packaage)
				ctxMatcher = mock.MatchedBy(func(c context.Context) bool {
					return assert.NotNil(t, identity.FromContext(c)) &&
						assert.NotEmpty(t,
							ctxhttpheader.FromContext(c, "Authorization"))
				})
			}

			db := mstore.DataStore{}
			db.On("AddDevice",
				ctxMatcher,
				mock.MatchedBy(
					func(d model.Device) bool {
						return d.IdData == idData
					})).Return(tc.addDeviceErr)

			db.On("GetDeviceByIdentityData",
				ctxMatcher,
				idData).Return(
				func(ctx context.Context, idata string) *model.Device {
					if tc.getDevByIdErr == nil {
						return &model.Device{
							PubKey: tc.getDevByIdKey,
							IdData: idata,
							Id:     devId,
						}
					}
					return nil
				},
				tc.getDevByIdErr)
			db.On("AddAuthSet",
				ctxMatcher,
				mock.MatchedBy(
					func(m model.AuthSet) bool {
						return m.DeviceId == devId
					})).Return(tc.addAuthSetErr)
			db.On("UpdateAuthSet",
				ctxMatcher,
				mock.MatchedBy(
					func(m model.AuthSet) bool {
						return m.DeviceId == devId
					}),
				mock.AnythingOfType("model.AuthSetUpdate")).Return(nil)
			db.On("GetAuthSetByDataKey",
				ctxMatcher,
				idData, pubKey).Return(
				func(ctx context.Context, idata string, key string) *model.AuthSet {
					if tc.getAuthSetErr == nil {
						return &model.AuthSet{
							Id:       authId,
							DeviceId: tc.getDevByKeyId,
							IdData:   idData,
							PubKey:   key,
							Status:   tc.devStatus,
						}
					}
					return nil
				},
				tc.getAuthSetErr)

			db.On("AddToken",
				ctxMatcher,
				mock.AnythingOfType("model.Token")).Return(nil)

			jwth := mjwt.Handler{}
			jwth.On("ToJWT",
				mock.MatchedBy(func(jt *jwt.Token) bool {
					t.Logf("token: %v", jt)
					return assert.NotNil(t, jt) &&
						assert.Equal(t, devId, jt.Claims.Subject) &&
						(tc.tenantVerify == false ||
							assert.Equal(t, "foobar", jt.Claims.Tenant))
				})).
				Return("dummytoken", nil)

			devauth := NewDevAuth(&db, nil, &jwth, Config{})

			if tc.tenantVerify {
				ct := mtenant.ClientRunner{}
				ct.On("VerifyToken",
					mtesting.ContextMatcher(),
					tc.inReq.TenantToken,
					mock.AnythingOfType("*apiclient.HttpApi")).
					Return(tc.tenantVerificationErr)
				devauth = devauth.WithTenantVerification(&ct)
			}

			res, err := devauth.SubmitAuthRequest(context.Background(), &tc.inReq)

			t.Logf("error: %v", err)
			assert.Equal(t, tc.res, res)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// still a Submit... test, but focuses on preauth
func TestDevAuthSubmitAuthRequestPreauth(t *testing.T) {
	t.Parallel()

	inReq := model.AuthReq{
		IdData:      "foo-iddata",
		PubKey:      "foo-pubkey",
		TenantToken: "foo-tenant",
	}

	dummyDevId := "dummydevid"
	dummyToken := "dummytoken"

	testCases := []struct {
		desc string

		dbGetAuthSetByDataKeyRes *model.AuthSet
		dbGetAuthSetByDataKeyErr error

		dbGetLimitRes *model.Limit
		dbGetLimitErr error

		dbGetDevCountByStatusRes int
		dbGetDevCountByStatusErr error

		dev                *model.Device
		dbGetDeviceByIdErr error

		coSubmitProvisionDeviceJobErr error

		res string
		err error
	}{
		{
			desc: "ok: preauthorized set is auto-accepted",
			dbGetAuthSetByDataKeyRes: &model.AuthSet{
				IdData:   inReq.IdData,
				DeviceId: dummyDevId,
				PubKey:   inReq.PubKey,
				Status:   model.DevStatusPreauth,
			},
			dbGetLimitRes: &model.Limit{
				Value: 5,
			},
			dbGetDevCountByStatusRes: 0,
			dev: &model.Device{
				Id:     dummyDevId,
				Status: model.DevStatusPending,
			},
			res: dummyToken,
		},
		{
			desc: "error: can't get an existing authset",
			dbGetAuthSetByDataKeyErr: errors.New("db error"),
			dev: &model.Device{
				Id:     dummyDevId,
				Status: model.DevStatusPending,
			},
			err: errors.New("failed to fetch auth set: db error"),
		},
		{
			desc: "error: preauthorized set would exceed limit",
			dbGetAuthSetByDataKeyRes: &model.AuthSet{
				IdData:   inReq.IdData,
				DeviceId: dummyDevId,
				PubKey:   inReq.PubKey,
				Status:   model.DevStatusPreauth,
			},
			dbGetLimitRes: &model.Limit{
				Value: 5,
			},
			dbGetDevCountByStatusRes: 5,
			dev: &model.Device{
				Id:     dummyDevId,
				Status: model.DevStatusPending,
			},
			err: ErrMaxDeviceCountReached,
		},
		{
			desc: "error: can't get device limit",
			dbGetAuthSetByDataKeyRes: &model.AuthSet{
				IdData:   inReq.IdData,
				DeviceId: dummyDevId,
				PubKey:   inReq.PubKey,
				Status:   model.DevStatusPreauth,
			},
			dbGetLimitErr: errors.New("db error"),
			dev: &model.Device{
				Id:     dummyDevId,
				Status: model.DevStatusPending,
			},
			err: errors.New("can't get current device limit: db error"),
		},
		{
			desc: "error: failed to submit job to conductor",
			dbGetAuthSetByDataKeyRes: &model.AuthSet{
				IdData:   inReq.IdData,
				DeviceId: dummyDevId,
				PubKey:   inReq.PubKey,
				Status:   model.DevStatusPreauth,
			},
			dbGetLimitRes: &model.Limit{
				Value: 5,
			},
			dbGetDevCountByStatusRes: 0,
			dev: &model.Device{
				Id:     dummyDevId,
				Status: model.DevStatusPending,
			},
			coSubmitProvisionDeviceJobErr: errors.New("conductor failed"),
			err: errors.New("submit device provisioning job error: conductor failed"),
		},
		{
			desc: "ok: preauthorized set is auto-accepted, device was already accepted",
			dbGetAuthSetByDataKeyRes: &model.AuthSet{
				IdData:   inReq.IdData,
				DeviceId: dummyDevId,
				PubKey:   inReq.PubKey,
				Status:   model.DevStatusPreauth,
			},
			dbGetLimitRes: &model.Limit{
				Value: 5,
			},
			dbGetDevCountByStatusRes: 0,
			dev: &model.Device{
				Id:     dummyDevId,
				Status: model.DevStatusAccepted,
			},
			coSubmitProvisionDeviceJobErr: errors.New("conductor shouldn't be called"),
			res: dummyToken,
		},
		{
			desc: "error: cannot get device status",
			dbGetAuthSetByDataKeyRes: &model.AuthSet{
				IdData:   inReq.IdData,
				DeviceId: dummyDevId,
				PubKey:   inReq.PubKey,
				Status:   model.DevStatusPreauth,
			},
			dbGetLimitRes: &model.Limit{
				Value: 5,
			},
			dbGetDevCountByStatusRes: 0,
			dbGetDeviceByIdErr:       errors.New("Get device failed"),
			err:                      errors.New("Get device failed"),
		},
	}

	for tcidx := range testCases {
		tc := testCases[tcidx]
		t.Run(fmt.Sprintf("tc: %s", tc.desc), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			// setup mocks
			db := mstore.DataStore{}

			// get the auth set to check if preauthorized
			db.On("GetAuthSetByDataKey",
				ctx,
				inReq.IdData,
				inReq.PubKey,
			).Return(
				tc.dbGetAuthSetByDataKeyRes,
				tc.dbGetAuthSetByDataKeyErr,
			)

			// for a preauthorized set - check if we're not over the limit
			db.On("GetLimit",
				ctx,
				model.LimitMaxDeviceCount,
			).Return(
				tc.dbGetLimitRes,
				tc.dbGetLimitErr,
			)

			// takes part in limit checking
			db.On("GetDevCountByStatus",
				ctx,
				model.DevStatusAccepted,
			).Return(
				tc.dbGetDevCountByStatusRes,
				tc.dbGetDevCountByStatusErr,
			)

			// at the end of processing, updates the preauthorized set to 'accepted'
			// just happy path, errors tested elsewhere
			db.On("UpdateAuthSet",
				ctx,
				mock.MatchedBy(
					func(m *model.AuthSet) bool {
						return m.DeviceId == dummyDevId

					}),
				mock.MatchedBy(
					func(u model.AuthSetUpdate) bool {
						return u.Status == model.DevStatusAccepted
					}),
			).Return(nil)

			// at the end of processing, updates the device status to 'accepted'
			db.On("UpdateDevice",
				ctx,
				mock.MatchedBy(
					func(m model.Device) bool {
						return m.Id == dummyDevId

					}),
				mock.MatchedBy(
					func(u model.DeviceUpdate) bool {
						return u.Status == model.DevStatusAccepted
					}),
			).Return(nil)

			// at the end of processing, saves the issued token
			// only happy path, errors tested elsewhere
			db.On("AddToken",
				ctx,
				mock.AnythingOfType("model.Token"),
			).Return(nil)

			db.On("GetDeviceById",
				context.Background(), dummyDevId).Return(tc.dev, tc.dbGetDeviceByIdErr)

			// token serialization - happy path only, errors tested elsewhere
			jwth := mjwt.Handler{}
			jwth.On("ToJWT",
				mock.AnythingOfType("*jwt.Token"),
			).Return(dummyToken, nil)

			co := morchestrator.ClientRunner{}
			co.On("SubmitProvisionDeviceJob", ctx,
				mock.AnythingOfType("orchestrator.ProvisionDeviceReq")).
				Return(tc.coSubmitProvisionDeviceJobErr)

			// setup devauth
			devauth := NewDevAuth(&db, &co, &jwth, Config{})

			// test
			res, err := devauth.SubmitAuthRequest(ctx, &inReq)

			// verify
			assert.Equal(t, tc.res, res)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthPreauthorizeDevice(t *testing.T) {
	t.Parallel()

	authsetId := "aid"
	deviceId := "did"
	idData := "iddata"
	pubKey := "pubkey"

	req := &model.PreAuthReq{
		AuthSetId: authsetId,
		DeviceId:  deviceId,
		IdData:    idData,
		PubKey:    pubKey,
	}

	testCases := []struct {
		desc string
		req  *model.PreAuthReq

		addDeviceErr  error
		addAuthSetErr error

		err error
	}{
		{
			desc: "ok",
			req:  req,
		},
		{
			desc: "error: add device, exists",
			req:  req,

			addDeviceErr: store.ErrObjectExists,

			err: ErrDeviceExists,
		},
		{
			desc: "error: add device, generic",
			req:  req,

			addDeviceErr: errors.New("generic error"),

			err: errors.New("failed to add device: generic error"),
		},
		{
			desc: "error: add auth set, exists",
			req:  req,

			addAuthSetErr: store.ErrObjectExists,

			err: ErrDeviceExists,
		},
		{
			desc: "error: add auth set, exists",
			req:  req,

			addAuthSetErr: errors.New("generic error"),

			err: errors.New("failed to add auth set: generic error"),
		},
	}

	for tcidx := range testCases {
		tc := testCases[tcidx]
		t.Run(fmt.Sprintf("tc: %s", tc.desc), func(t *testing.T) {
			t.Parallel()

			ctxMatcher := mtesting.ContextMatcher()

			ctxMatcher = mock.MatchedBy(func(c context.Context) bool {
				return true
			})

			db := mstore.DataStore{}
			db.On("AddDevice",
				ctxMatcher,
				mock.MatchedBy(
					func(d model.Device) bool {
						return (d.IdData == tc.req.IdData) &&
							(d.Id == tc.req.DeviceId) &&
							(d.PubKey == tc.req.PubKey)
					})).Return(tc.addDeviceErr)

			db.On("AddAuthSet",
				ctxMatcher,
				mock.MatchedBy(
					func(m model.AuthSet) bool {
						return (m.Id == tc.req.AuthSetId) &&
							(m.DeviceId == tc.req.DeviceId) &&
							(m.IdData == tc.req.IdData) &&
							(m.PubKey == tc.req.PubKey)
					})).Return(tc.addAuthSetErr)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			err := devauth.PreauthorizeDevice(context.Background(), tc.req)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthAcceptDevice(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		aset *model.AuthSet

		dbLimit    *model.Limit
		dbLimitErr error

		dbCount    int
		dbCountErr error

		dev                *model.Device
		dbGetDeviceByIdErr error

		dbUpdateErr               error
		dbUpdateRevokeAuthSetsErr error

		dbGetErr error

		coSubmitProvisionDeviceJobErr error

		outErr string
	}{
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbLimit: &model.Limit{Value: 0},
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbLimit: &model.Limit{Value: 5},
			dbCount: 4,
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
				Status:   model.DevStatusAccepted,
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			coSubmitProvisionDeviceJobErr: errors.New("conductor shouldn't be called"),
			dbLimit: &model.Limit{Value: 5},
			dbCount: 4,
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
				Status:   model.DevStatusPending,
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusAccepted,
			},
			coSubmitProvisionDeviceJobErr: errors.New("conductor shouldn't be called"),
			dbLimit: &model.Limit{Value: 5},
			dbCount: 4,
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbLimit: &model.Limit{Value: 5},
			dbCount: 5,
			outErr:  "maximum number of accepted devices reached",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbLimit: &model.Limit{Value: 5},
			dbCount: 6,
			outErr:  "maximum number of accepted devices reached",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbLimit:    &model.Limit{Value: 5},
			dbLimitErr: errors.New("error"),
			outErr:     "can't get current device limit: error",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbLimit:    &model.Limit{Value: 5},
			dbCountErr: errors.New("error"),
			outErr:     "can't get current device count: error",
		},
		{
			dbLimit:  &model.Limit{Value: 0},
			dbGetErr: store.ErrDevNotFound,
			outErr:   store.ErrDevNotFound.Error(),
		},
		{
			dbLimit: &model.Limit{Value: 0},
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbUpdateErr: errors.New("failed to update device"),
			outErr:      "db update device auth set error: failed to update device",
		},
		{
			dbLimit: &model.Limit{Value: 0},
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			coSubmitProvisionDeviceJobErr: errors.New("conductor failed"),
			outErr: "submit device provisioning job error: conductor failed",
		},
		{
			dbLimit: &model.Limit{Value: 0},
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbUpdateRevokeAuthSetsErr: store.ErrAuthSetNotFound,
		},
		{
			dbLimit: &model.Limit{Value: 0},
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dev: &model.Device{
				Id:     "dummy_devid",
				Status: model.DevStatusPending,
			},
			dbUpdateRevokeAuthSetsErr: errors.New("foobar"),
			outErr: "failed to reject auth sets: foobar",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbLimit:            &model.Limit{Value: 5},
			dbCount:            4,
			dbGetDeviceByIdErr: errors.New("Get device failed"),
			outErr:             "Get device failed",
		},
	}

	for idx := range testCases {
		tc := testCases[idx]
		t.Run(fmt.Sprintf("tc %v", idx), func(t *testing.T) {
			t.Parallel()

			db := mstore.DataStore{}
			db.On("GetAuthSetById",
				context.Background(), "dummy_aid").Return(tc.aset, tc.dbGetErr)
			db.On("GetLimit",
				context.Background(), model.LimitMaxDeviceCount).Return(tc.dbLimit, tc.dbLimitErr)
			db.On("GetDevCountByStatus",
				context.Background(), model.DevStatusAccepted).Return(tc.dbCount, tc.dbCountErr)
			db.On("GetDeviceById",
				context.Background(), "dummy_devid").Return(tc.dev, tc.dbGetDeviceByIdErr)
			db.On("UpdateDevice", context.Background(),
				mock.AnythingOfType("model.Device"),
				mock.AnythingOfType("model.DeviceUpdate")).Return(nil)

			if tc.aset != nil {
				// for rejecting all auth sets
				db.On("UpdateAuthSet",
					context.Background(),
					mock.MatchedBy(
						func(m bson.M) bool {
							return m[model.AuthSetKeyDeviceId] == tc.aset.DeviceId
						}),
					model.AuthSetUpdate{
						Status: model.DevStatusRejected,
					}).Return(tc.dbUpdateRevokeAuthSetsErr)
				// for accepting a single one
				db.On("UpdateAuthSet", context.Background(),
					*tc.aset,
					model.AuthSetUpdate{
						Status: model.DevStatusAccepted,
					}).Return(tc.dbUpdateErr)
			}

			ctx := context.Background()

			co := morchestrator.ClientRunner{}
			co.On("SubmitProvisionDeviceJob", ctx,
				mock.AnythingOfType("orchestrator.ProvisionDeviceReq")).
				Return(tc.coSubmitProvisionDeviceJobErr)

			devauth := NewDevAuth(&db, &co, nil, Config{})
			err := devauth.AcceptDeviceAuth(context.Background(), "dummy_devid", "dummy_aid")

			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthRejectDevice(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		aset             *model.AuthSet
		dbErr            error
		dbDelDevTokenErr error

		outErr string
	}{
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbDelDevTokenErr: nil,
		},
		{
			dbErr:            errors.New("failed"),
			dbDelDevTokenErr: nil,
			outErr:           "db get auth set error: failed",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbDelDevTokenErr: store.ErrTokenNotFound,
			outErr:           "db delete device token error: token not found",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
				Status:   "accepted",
			},
			dbDelDevTokenErr: errors.New("some error"),
			outErr:           "db delete device token error: some error",
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			db := mstore.DataStore{}
			db.On("GetAuthSetById", context.Background(), "dummy_aid").Return(tc.aset, tc.dbErr)
			if tc.aset != nil {
				db.On("UpdateAuthSet", context.Background(), *tc.aset,
					model.AuthSetUpdate{Status: model.DevStatusRejected}).Return(nil)
			}
			db.On("DeleteTokenByDevId", context.Background(), "dummy_devid").Return(
				tc.dbDelDevTokenErr)
			db.On("GetDeviceStatus", context.Background(),
				"dummy_devid").Return(
				"accpted", nil)
			db.On("UpdateDevice", context.Background(),
				mock.AnythingOfType("model.Device"),
				mock.AnythingOfType("model.DeviceUpdate")).Return(nil)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			err := devauth.RejectDeviceAuth(context.Background(), "dummy_devid", "dummy_aid")

			if tc.dbErr != nil || (tc.dbDelDevTokenErr != nil &&
				tc.dbDelDevTokenErr != store.ErrTokenNotFound) {

				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthResetDevice(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		aset             *model.AuthSet
		dbErr            error
		dbDelDevTokenErr error

		outErr string
	}{
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbDelDevTokenErr: nil,
		},
		{
			dbErr:  errors.New("failed"),
			outErr: "db get auth set error: failed",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
				Status:   "accepted",
			},
			dbDelDevTokenErr: store.ErrTokenNotFound,
			outErr:           "db delete device token error: token not found",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
				Status:   "accepted",
			},
			dbDelDevTokenErr: errors.New("some error"),
			outErr:           "db delete device token error: some error",
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			db := mstore.DataStore{}
			db.On("GetAuthSetById", context.Background(), "dummy_aid").Return(tc.aset, tc.dbErr)
			if tc.aset != nil {
				db.On("UpdateAuthSet", context.Background(), *tc.aset,
					model.AuthSetUpdate{Status: model.DevStatusPending}).Return(nil)
			}
			db.On("DeleteTokenByDevId", context.Background(), "dummy_devid").Return(
				tc.dbDelDevTokenErr)
			db.On("GetDeviceStatus", context.Background(),
				"dummy_devid").Return(
				"accpted", nil)
			db.On("UpdateDevice", context.Background(),
				mock.AnythingOfType("model.Device"),
				mock.AnythingOfType("model.DeviceUpdate")).Return(nil)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			err := devauth.ResetDeviceAuth(context.Background(), "dummy_devid", "dummy_aid")

			if tc.dbErr != nil ||
				(tc.dbDelDevTokenErr != nil &&
					tc.dbDelDevTokenErr != store.ErrTokenNotFound) {

				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthVerifyToken(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		tokenString      string
		tokenValidateErr error

		jwToken     *jwt.Token
		validateErr error

		token       *model.Token
		getTokenErr error

		auth       *model.AuthSet
		getAuthErr error

		dev          *model.Device
		getDeviceErr error

		tenantVerify bool
	}{
		{
			tokenString:      "expired",
			tokenValidateErr: jwt.ErrTokenExpired,

			jwToken: &jwt.Token{
				Claims: jwt.Claims{
					ID: "expired",
				},
			},
			validateErr: jwt.ErrTokenExpired,
		},
		{
			tokenString:      "bad",
			tokenValidateErr: jwt.ErrTokenInvalid,

			jwToken:     nil,
			validateErr: jwt.ErrTokenInvalid,
		},
		{
			tokenString:      "good-no-auth",
			tokenValidateErr: store.ErrDevNotFound,

			jwToken: &jwt.Token{
				Claims: jwt.Claims{
					ID:     "good-no-auth",
					Device: true,
				},
			},
			token: &model.Token{
				Id:        "good-no-auth",
				AuthSetId: "not-found",
			},
			getAuthErr: store.ErrDevNotFound,
		},
		{
			tokenString: "good-accepted",
			jwToken: &jwt.Token{
				Claims: jwt.Claims{
					ID:     "good-accepted",
					Device: true,
				},
			},
			token: &model.Token{
				Id:        "good-accepted",
				AuthSetId: "foo",
			},
			auth: &model.AuthSet{
				Id:       "foo",
				Status:   model.DevStatusAccepted,
				DeviceId: "foodev",
			},
			dev: &model.Device{
				Id:              "foodev",
				Decommissioning: false,
			},
		},
		{
			tokenString:      "good-rejected",
			tokenValidateErr: jwt.ErrTokenInvalid,

			jwToken: &jwt.Token{
				Claims: jwt.Claims{
					ID:     "good-rejected",
					Device: true,
				},
			},
			token: &model.Token{
				Id:        "good-rejected",
				AuthSetId: "foo",
			},
			auth: &model.AuthSet{
				Id:     "foo",
				Status: model.DevStatusRejected,
			},
		},
		{
			tokenString:      "good-accepted-decommissioning",
			tokenValidateErr: jwt.ErrTokenInvalid,

			jwToken: &jwt.Token{
				Claims: jwt.Claims{
					ID:     "good-accepted-decommissioning",
					Device: true,
				},
			},
			token: &model.Token{
				Id:        "good-accepted-decommissioning",
				AuthSetId: "foo",
			},
			auth: &model.AuthSet{
				Id:       "foo",
				Status:   model.DevStatusAccepted,
				DeviceId: "foodev",
			},
			dev: &model.Device{
				Id:              "foodev",
				Decommissioning: true,
			},
		},
		{
			tokenString:      "missing-tenant-claim",
			tokenValidateErr: jwt.ErrTokenInvalid,

			jwToken: &jwt.Token{
				Claims: jwt.Claims{
					ID: "missing-tenant-claim",
				},
			},

			tenantVerify: true,
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %s", tc.tokenString), func(t *testing.T) {
			t.Parallel()

			db := &mstore.DataStore{}
			ja := &mjwt.Handler{}

			devauth := NewDevAuth(db, nil, ja, Config{})
			if tc.tenantVerify {
				// ok to pass nil tenantadm client here
				devauth = devauth.WithTenantVerification(nil)
			}

			// ja.On("FromJWT", tc.tokenString).Return(tc.jwToken, tc.validateErr)
			ja.On("FromJWT", tc.tokenString).Return(
				func(s string) *jwt.Token {
					t.Logf("string: %v return %+v", s, tc.jwToken)
					return tc.jwToken
				}, tc.validateErr)

			if tc.validateErr == jwt.ErrTokenExpired {
				db.On("DeleteToken",
					context.Background(),
					tc.jwToken.Claims.ID).Return(nil)
			}

			if tc.token != nil {
				db.On("GetToken", context.Background(),
					tc.jwToken.Claims.ID).
					Return(tc.token, tc.getTokenErr)
			}

			if tc.token != nil {
				db.On("GetAuthSetById", context.Background(),
					tc.token.AuthSetId).Return(tc.auth, tc.getAuthErr)
				// devauth will ask for a device if auth set is
				// found and accepted
				if tc.dev != nil {
					db.On("GetDeviceById", context.Background(),
						tc.auth.DeviceId).Return(tc.dev, tc.getDeviceErr)
				}
			}

			err := devauth.VerifyToken(context.Background(), tc.tokenString)
			if tc.tokenValidateErr != nil {
				assert.EqualError(t, err, tc.tokenValidateErr.Error())
			} else {
				assert.NoError(t, err)
			}
			ja.AssertExpectations(t)
			db.AssertExpectations(t)

		})
	}
}

func TestDevAuthDecommissionDevice(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		devId string

		dbUpdateDeviceErr            error
		dbDeleteAuthSetsForDeviceErr error
		dbDeleteTokenByDevIdErr      error
		dbDeleteDeviceErr            error

		coSubmitDeviceDecommisioningJobErr error
		coAuthorization                    string

		outErr string
	}{
		{
			devId:             "devId1",
			dbUpdateDeviceErr: errors.New("UpdateDevice Error"),
			outErr:            "UpdateDevice Error",
		},
		{
			devId: "devId2",
			dbDeleteAuthSetsForDeviceErr: errors.New("DeleteAuthSetsForDevice Error"),
			outErr: "db delete device authorization sets error: DeleteAuthSetsForDevice Error",
		},
		{
			devId: "devId3",
			dbDeleteTokenByDevIdErr: errors.New("DeleteTokenByDevId Error"),
			outErr:                  "db delete device tokens error: DeleteTokenByDevId Error",
		},
		{
			devId:             "devId4",
			dbUpdateDeviceErr: errors.New("DeleteDevice Error"),
			outErr:            "DeleteDevice Error",
		},
		{
			devId: "devId5",
			coSubmitDeviceDecommisioningJobErr: errors.New("SubmitDeviceDecommisioningJob Error"),
			outErr: "submit device decommissioning job error: SubmitDeviceDecommisioningJob Error",
		},
		{
			devId:           "devId6",
			coAuthorization: "Bearer foobar",
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			if tc.coAuthorization != "" {
				ctx = ctxhttpheader.WithContext(ctx, http.Header{
					"Authorization": []string{tc.coAuthorization},
				}, "Authorization")
			}

			co := morchestrator.ClientRunner{}
			co.On("SubmitDeviceDecommisioningJob", ctx,
				orchestrator.DecommissioningReq{
					DeviceId:      tc.devId,
					Authorization: tc.coAuthorization,
				}).
				Return(tc.coSubmitDeviceDecommisioningJobErr)

			db := mstore.DataStore{}
			db.On("UpdateDevice", ctx,
				model.Device{Id: tc.devId},
				model.DeviceUpdate{
					Decommissioning: to.BoolPtr(true),
				}).Return(
				tc.dbUpdateDeviceErr)
			db.On("DeleteAuthSetsForDevice", ctx,
				tc.devId).Return(
				tc.dbDeleteAuthSetsForDeviceErr)
			db.On("DeleteTokenByDevId", ctx,
				tc.devId).Return(
				tc.dbDeleteTokenByDevIdErr)
			db.On("DeleteDevice", ctx,
				tc.devId).Return(
				tc.dbDeleteDeviceErr)
			db.On("UpdateDevice", ctx,
				mock.AnythingOfType("model.Device"),
				mock.AnythingOfType("model.DeviceUpdate")).Return(nil)

			devauth := NewDevAuth(&db, &co, nil, Config{})
			err := devauth.DecommissionDevice(ctx, tc.devId)

			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthSetTenantLimit(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		tenantId string

		dbPutLimitErr error
		limit         model.Limit

		outErr string
	}{
		{
			tenantId:      "tenant1",
			dbPutLimitErr: errors.New("PutLimit error"),
			outErr:        "failed to save limit {foobar 1234} for tenant tenant1 to database: PutLimit error",
			limit: model.Limit{
				Name:  "foobar",
				Value: 1234,
			},
		},
		{
			tenantId: "tenant2",
			limit: model.Limit{
				Name:  "foobar2",
				Value: 9999999,
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			db := mstore.DataStore{}
			db.On("PutLimit",
				mock.MatchedBy(func(ctx context.Context) bool {
					ident := identity.FromContext(ctx)
					return assert.NotNil(t, ident) &&
						assert.Equal(t, tc.tenantId, ident.Tenant)
				}),
				tc.limit).
				Return(tc.dbPutLimitErr)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			err := devauth.SetTenantLimit(ctx, tc.tenantId, tc.limit)

			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthGetLimit(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		inName string

		dbLimit *model.Limit
		dbErr   error

		outLimit *model.Limit
		outErr   error

		maxDevicesLimitDefaultConfig uint64
	}{
		"ok": {
			inName: "other_limit",

			dbLimit: &model.Limit{Name: "other_limit", Value: 123},
			dbErr:   nil,

			outLimit: &model.Limit{Name: "other_limit", Value: 123},
			outErr:   nil,

			maxDevicesLimitDefaultConfig: 456,
		},
		"ok max_devices": {
			inName: model.LimitMaxDeviceCount,

			dbLimit: &model.Limit{Name: model.LimitMaxDeviceCount, Value: 123},
			dbErr:   nil,

			outLimit: &model.Limit{Name: model.LimitMaxDeviceCount, Value: 123},
			outErr:   nil,

			maxDevicesLimitDefaultConfig: 456,
		},
		"limit not found": {
			inName: "other_limit",

			dbLimit: nil,
			dbErr:   store.ErrLimitNotFound,

			outLimit: &model.Limit{Name: "other_limit", Value: 0},
			outErr:   nil,

			maxDevicesLimitDefaultConfig: 456,
		},
		"limit not found max_devices": {
			inName: model.LimitMaxDeviceCount,

			dbLimit: nil,
			dbErr:   store.ErrLimitNotFound,

			outLimit: &model.Limit{Name: model.LimitMaxDeviceCount, Value: 456},
			outErr:   nil,

			maxDevicesLimitDefaultConfig: 456,
		},
		"generic error": {
			inName: "max_devices",

			dbLimit: nil,
			dbErr:   errors.New("db error"),

			outLimit: nil,
			outErr:   errors.New("db error"),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %s", i), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			db := mstore.DataStore{}
			db.On("GetLimit", ctx, tc.inName).Return(tc.dbLimit, tc.dbErr)
			db.On("UpdateDevice", ctx,
				mock.AnythingOfType("model.Device"),
				mock.AnythingOfType("model.DeviceUpdate")).Return(nil)

			devauth := NewDevAuth(&db, nil, nil,
				Config{MaxDevicesLimitDefault: tc.maxDevicesLimitDefaultConfig})
			limit, err := devauth.GetLimit(ctx, tc.inName)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, *tc.outLimit, *limit)
			}
		})
	}
}

func TestDevAuthGetTenantLimit(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		inName   string
		inTenant string

		dbLimit *model.Limit
		dbErr   error

		outLimit *model.Limit
		outErr   error
	}{
		"ok": {
			inName:   "max_devices",
			inTenant: "tenant-foo",

			dbLimit: &model.Limit{Name: "max_devices", Value: 123},
			dbErr:   nil,

			outLimit: &model.Limit{Name: "max_devices", Value: 123},
			outErr:   nil,
		},
		"limit not found": {
			inName:   "max_devices",
			inTenant: "tenant-bar",

			dbLimit: nil,
			dbErr:   store.ErrLimitNotFound,

			outLimit: &model.Limit{Name: "max_devices", Value: 0},
			outErr:   nil,
		},
		"generic error": {
			inName:   "max_devices",
			inTenant: "tenant-baz",

			dbLimit: nil,
			dbErr:   errors.New("db error"),

			outLimit: nil,
			outErr:   errors.New("db error"),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %s", i), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			db := mstore.DataStore{}
			// in get limit, verify the correct db was set
			verifyCtx := func(args mock.Arguments) {
				ctx := args.Get(0).(context.Context)
				id := identity.FromContext(ctx)
				assert.Equal(t, tc.inTenant, id.Tenant)
			}

			ctxMatcher := mock.MatchedBy(func(c context.Context) bool {
				return assert.NotNil(t, identity.FromContext(c))
			})

			db.On("GetLimit", ctxMatcher, tc.inName).
				Run(verifyCtx).
				Return(tc.dbLimit, tc.dbErr)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			limit, err := devauth.GetTenantLimit(ctx, tc.inName, tc.inTenant)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, *tc.outLimit, *limit)
			}
		})
	}
}

func TestDevAuthGetDevCountByStatus(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		status string

		dbCnt int
		dbErr error

		cnt int
		err error
	}{
		"ok": {
			status: "pending",

			dbCnt: 5,
			dbErr: nil,

			cnt: 5,
			err: nil,
		},
		"ok 2": {
			status: "accepted",

			dbCnt: 0,
			dbErr: nil,

			cnt: 0,
			err: nil,
		},
		"generic error": {
			status: "accepted",

			dbCnt: 5,
			dbErr: errors.New("db error"),

			err: errors.New("db error"),
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %s", i), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			db := mstore.DataStore{}
			db.On("GetDevCountByStatus", ctx, tc.status).Return(tc.dbCnt, tc.dbErr)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			cnt, err := devauth.GetDevCountByStatus(ctx, tc.status)

			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.cnt, cnt)
			}
		})
	}
}

func TestDevAuthProvisionTenant(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		datastoreError error
		outError       error
	}{
		"ok": {
			datastoreError: nil,
			outError:       nil,
		},
		"generic error": {
			datastoreError: errors.New("failed to provision tenant"),
			outError:       errors.New("failed to provision tenant"),
		},
	}

	for name, tc := range testCases {
		t.Run(fmt.Sprintf("test case: %s", name), func(t *testing.T) {
			ctx := context.Background()

			db := mstore.DataStore{}
			db.On("MigrateTenant", ctx,
				mock.AnythingOfType("string"),
				"1.3.0",
			).Return(tc.datastoreError)
			db.On("WithAutomigrate").Return(&db)
			devauth := NewDevAuth(&db, nil, nil, Config{})

			err := devauth.ProvisionTenant(ctx, "foo")

			if tc.outError != nil {
				if assert.Error(t, err) {
					assert.EqualError(t, err, tc.outError.Error())
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDevAuthDeleteAuthSet(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		devId  string
		authId string

		dbGetAuthSetByIdErr         error
		dbDeleteTokenByDevIdErr     error
		dbDeleteAuthSetForDeviceErr error
		dbGetAuthSetsForDeviceErr   error
		dbDeleteDeviceErr           error
		dbGetDeviceStatusErr        error
		dbUpdateDeviceErr           error

		authSet *model.AuthSet

		outErr string
	}{
		{
			devId:               "devId1",
			authId:              "authId1",
			dbGetAuthSetByIdErr: errors.New("GetAuthSetById Error"),
			outErr:              "db get auth set error: GetAuthSetById Error",
		},
		{
			devId:               "devId2",
			authId:              "authId2",
			dbGetAuthSetByIdErr: store.ErrAuthSetNotFound,
			outErr:              "db get auth set error: authorization set not found",
		},
		{
			devId:                   "devId3",
			authId:                  "authId3",
			authSet:                 &model.AuthSet{Status: model.DevStatusAccepted},
			dbDeleteTokenByDevIdErr: errors.New("DeleteTokenByDevId Error"),
			outErr:                  "db delete device tokens error: DeleteTokenByDevId Error",
		},
		{
			devId:                   "devId4",
			authId:                  "authId4",
			authSet:                 &model.AuthSet{Status: model.DevStatusPending},
			dbDeleteTokenByDevIdErr: errors.New("DeleteTokenByDevId Error"),
		},
		{
			devId:                   "devId5",
			authId:                  "authId5",
			dbDeleteTokenByDevIdErr: store.ErrTokenNotFound,
		},
		{
			devId:  "devId6",
			authId: "authId6",
			dbDeleteAuthSetForDeviceErr: errors.New("DeleteAuthSetsForDevice Error"),
			outErr: "DeleteAuthSetsForDevice Error",
		},
		{
			devId:             "devId8",
			authId:            "authId8",
			authSet:           &model.AuthSet{Status: model.DevStatusPreauth},
			dbDeleteDeviceErr: errors.New("DeleteDevice Error"),
			outErr:            "DeleteDevice Error",
		},
		{
			devId:             "devId9",
			authId:            "authId9",
			dbDeleteDeviceErr: errors.New("DeleteDevice Error"),
		},
		{
			devId:                "devId10",
			authId:               "authId10",
			dbGetDeviceStatusErr: errors.New("Get Device Status Error"),
			outErr:               "Cannot determine device status: Get Device Status Error",
		},
		{
			devId:             "devId11",
			authId:            "authId11",
			dbUpdateDeviceErr: errors.New("Update Device Error"),
			outErr:            "failed to update device status: Update Device Error",
		},
		{
			devId:  "devId12",
			authId: "authId12",
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			authSet := &model.AuthSet{Status: model.DevStatusPending}
			if tc.authSet != nil {
				authSet = tc.authSet
			}

			db := mstore.DataStore{}
			db.On("GetAuthSetById", ctx,
				tc.authId).Return(
				authSet,
				tc.dbGetAuthSetByIdErr)
			db.On("DeleteAuthSetForDevice", ctx,
				tc.devId, tc.authId).Return(
				tc.dbDeleteAuthSetForDeviceErr)
			db.On("DeleteTokenByDevId", ctx,
				tc.devId).Return(
				tc.dbDeleteTokenByDevIdErr)
			db.On("DeleteDevice", ctx,
				tc.devId).Return(
				tc.dbDeleteDeviceErr)
			db.On("GetDeviceStatus", ctx,
				tc.devId).Return(
				"accpted", tc.dbGetDeviceStatusErr)
			db.On("UpdateDevice", ctx,
				mock.AnythingOfType("model.Device"),
				mock.AnythingOfType("model.DeviceUpdate")).Return(tc.dbUpdateDeviceErr)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			err := devauth.DeleteAuthSet(ctx, tc.devId, tc.authId)

			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)
				if authSet.Status == model.DevStatusPreauth {
					db.AssertCalled(t, "DeleteDevice", tc.devId)
				} else {
					db.AssertNotCalled(t, "DeleteDevice", tc.devId)
				}
			}
		})
	}
}

func TestDeleteTokens(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		tenantId string
		deviceId string

		dbErrDeleteTokenById error
		dbErrDeleteTokens    error

		outErr error
	}{
		"ok, all tenant's devs": {
			tenantId: "foo",
			deviceId: "dev-foo",
		},
		"ok, single dev": {
			tenantId: "foo",
		},
		"ok, single dev, token not found": {
			tenantId:             "foo",
			dbErrDeleteTokenById: store.ErrTokenNotFound,
		},
		"error, single dev": {
			tenantId:             "foo",
			deviceId:             "dev-foo",
			dbErrDeleteTokenById: errors.New("db error"),
			outErr:               errors.New("failed to delete tokens for tenant: foo, device id: dev-foo: db error"),
		},
		"error, all tenant's devs": {
			tenantId:          "foo",
			dbErrDeleteTokens: errors.New("db error"),
			outErr:            errors.New("failed to delete tokens for tenant: foo, device id: : db error"),
		},
	}

	for n := range testCases {
		tc := testCases[n]
		t.Run(fmt.Sprintf("tc %s", n), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			ctxMatcher := mtesting.ContextMatcher()

			db := mstore.DataStore{}
			db.On("DeleteTokenByDevId", ctxMatcher, tc.deviceId).
				Return(tc.dbErrDeleteTokenById)
			db.On("DeleteTokens", ctxMatcher).
				Return(tc.dbErrDeleteTokens)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			err := devauth.DeleteTokens(ctx, tc.tenantId, tc.deviceId)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetTenantDeviceStatus(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		tenantId string
		deviceId string

		dev                *model.Device
		dbGetDeviceByIdErr error

		outErr    error
		outStatus model.Status
	}{
		"ok": {
			tenantId: "foo",
			deviceId: "dev-foo",

			dev: &model.Device{
				Id:     "dev-foo",
				Status: model.DevStatusAccepted,
			},

			outStatus: model.Status{Status: "accepted"},
		},
		"error, not found": {
			tenantId: "foo",
			deviceId: "dev-foo",

			dbGetDeviceByIdErr: store.ErrDevNotFound,
			outErr:             ErrDeviceNotFound,
		},
		"error, generic": {
			tenantId: "foo",
			deviceId: "dev-foo",

			dbGetDeviceByIdErr: errors.New("get device error"),
			outErr:             errors.New("get device dev-foo failed: get device error"),
		},
	}

	for n := range testCases {
		tc := testCases[n]
		t.Run(fmt.Sprintf("tc %s", n), func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			ctxMatcher := mock.MatchedBy(func(c context.Context) bool {
				ident := identity.FromContext(c)
				assert.NotNil(t, ident)
				assert.Equal(t, tc.tenantId, ident.Tenant)

				return true
			})

			db := mstore.DataStore{}
			db.On("GetDeviceById",
				ctxMatcher,
				tc.deviceId,
			).Return(tc.dev, tc.dbGetDeviceByIdErr)

			devauth := NewDevAuth(&db, nil, nil, Config{})
			status, err := devauth.GetTenantDeviceStatus(ctx, tc.tenantId, tc.deviceId)

			if tc.outErr != nil {
				assert.EqualError(t, err, tc.outErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.outStatus, *status)
			}
		})
	}
}
