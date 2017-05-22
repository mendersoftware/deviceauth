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
package devauth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mendersoftware/deviceauth/client/deviceadm"
	mdevadm "github.com/mendersoftware/deviceauth/client/deviceadm/mocks"
	"github.com/mendersoftware/deviceauth/client/inventory"
	minventory "github.com/mendersoftware/deviceauth/client/inventory/mocks"
	morchestrator "github.com/mendersoftware/deviceauth/client/orchestrator/mocks"
	"github.com/mendersoftware/deviceauth/client/tenant"
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

		admissionNotified bool

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
			//admission was notified, so we should get a token right
			//away
			desc: "known, accepted, give out token",

			inReq: req,

			addDeviceErr:  store.ErrObjectExists,
			addAuthSetErr: store.ErrObjectExists,

			devStatus:     model.DevStatusAccepted,
			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			admissionNotified: true,

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

			admissionNotified: true,

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

			admissionNotified: true,

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
			//new device - admission error
			desc: "new device, admission request fail",

			inReq: req,

			getDevByKeyId: devId,
			devAdmErr:     errors.New("failed to add device"),

			err: errors.New("devadm add device error: failed to add device"),
		},
		{
			//new device - tenant token verification failed
			desc: "new device, tenant token verification fail",

			inReq: req,

			err: ErrDevAuthUnauthorized,

			tenantVerify:          true,
			tenantVerificationErr: tenant.ErrTokenVerificationFailed,
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

			admissionNotified: true,

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

			admissionNotified: true,

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
				// tenant verification is enabled
				ctxMatcher = mock.MatchedBy(func(c context.Context) bool {
					return assert.NotNil(t, identity.FromContext(c))
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
				mock.MatchedBy(
					func(m model.AuthSetUpdate) bool {
						return to.Bool(m.AdmissionNotified) == true
					})).Return(nil)

			db.On("GetAuthSetByDataKey",
				ctxMatcher,
				idData, pubKey).Return(
				func(ctx context.Context, idata string, key string) *model.AuthSet {
					if tc.getAuthSetErr == nil {
						return &model.AuthSet{
							Id:                authId,
							DeviceId:          tc.getDevByKeyId,
							IdData:            idData,
							PubKey:            key,
							Status:            tc.devStatus,
							AdmissionNotified: to.BoolPtr(tc.admissionNotified),
						}
					}
					return nil
				},
				tc.getAuthSetErr)

			db.On("AddToken",
				ctxMatcher,
				mock.AnythingOfType("model.Token")).Return(nil)

			cda := mdevadm.ClientRunner{}
			if !tc.admissionNotified {
				// setup admission client mock only if admission
				// was not notified yet as per test case
				cda.On("AddDevice",
					ctxMatcher,
					mock.MatchedBy(func(r deviceadm.AdmReq) bool {
						return (r.AuthId == authId) &&
							(r.IdData == idData) &&
							(r.DeviceId == devId) &&
							(r.PubKey == pubKey)
					}),
					mock.AnythingOfType("*apiclient.HttpApi")).
					Return(tc.devAdmErr)
			}

			cdi := minventory.ClientRunner{}

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

			devauth := NewDevAuth(&db, &cda, &cdi, nil, &jwth, Config{})

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

func TestDevAuthAcceptDevice(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		aset        *model.AuthSet
		dbUpdateErr error
		dbGetErr    error
		invErr      error

		outErr string
	}{
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
		},
		{
			dbGetErr: store.ErrDevNotFound,
			outErr:   store.ErrDevNotFound.Error(),
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbUpdateErr: errors.New("failed to update device"),
			outErr:      "db update device auth set error: failed to update device",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			invErr: errors.New("inventory failed"),
			outErr: "inventory device add error: failed to add device to inventory: inventory failed",
		},
	}

	for idx := range testCases {
		tc := testCases[idx]
		t.Run(fmt.Sprintf("tc %v", idx), func(t *testing.T) {
			t.Parallel()

			db := mstore.DataStore{}
			db.On("GetAuthSetById", context.Background(), "dummy_aid").Return(tc.aset, tc.dbGetErr)
			if tc.aset != nil {
				db.On("UpdateAuthSet", context.Background(), *tc.aset,
					model.AuthSetUpdate{Status: model.DevStatusAccepted}).Return(tc.dbUpdateErr)
			}

			inv := minventory.ClientRunner{}
			inv.On("AddDevice", context.Background(),
				inventory.AddReq{Id: "dummy_devid"},
				mock.AnythingOfType("*apiclient.HttpApi")).
				Return(tc.invErr)

			devauth := NewDevAuth(&db, nil, &inv, nil, nil, Config{})
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

			devauth := NewDevAuth(&db, nil, nil, nil, nil, Config{})
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
			},
			dbDelDevTokenErr: store.ErrTokenNotFound,
			outErr:           "db delete device token error: token not found",
		},
		{
			aset: &model.AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
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

			devauth := NewDevAuth(&db, nil, nil, nil, nil, Config{})
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
					ID: "good-no-auth",
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
					ID: "good-accepted",
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
					ID: "good-rejected",
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
					ID: "good-accepted-decommissioning",
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

			devauth := NewDevAuth(db, nil, nil, nil, ja, Config{})
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

			if tc.jwToken != nil {
				db.On("GetToken", context.Background(),
					tc.jwToken.Claims.ID).
					Return(tc.token, tc.getTokenErr)
			}

			if tc.token != nil {
				db.On("GetAuthSetById", context.Background(),
					tc.token.AuthSetId).Return(tc.auth, tc.getAuthErr)
				// devauth will ask for a device if auth set is
				// found and accepted
				if tc.auth != nil {
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

		})
	}
}

func TestDevAuthDecommissionDevice(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		dbUpdateDeviceErr                  error
		dbDeleteAuthSetsForDeviceErr       error
		dbDeleteTokenByDevIdErr            error
		dbDeleteDeviceErr                  error
		coSubmitDeviceDecommisioningJobErr error

		outErr string
	}{
		{
			dbUpdateDeviceErr: errors.New("UpdateDevice Error"),
			outErr:            "UpdateDevice Error",
		},
		{
			dbDeleteAuthSetsForDeviceErr: errors.New("DeleteAuthSetsForDevice Error"),
			outErr: "db delete device authorization sets error: DeleteAuthSetsForDevice Error",
		},
		{
			dbDeleteTokenByDevIdErr: errors.New("DeleteTokenByDevId Error"),
			outErr:                  "db delete device tokens error: DeleteTokenByDevId Error",
		},
		{
			dbUpdateDeviceErr: errors.New("DeleteDevice Error"),
			outErr:            "DeleteDevice Error",
		},
		{
			coSubmitDeviceDecommisioningJobErr: errors.New("SubmitDeviceDecommisioningJob Error"),
			outErr: "submit device decommissioning job error: SubmitDeviceDecommisioningJob Error",
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			co := morchestrator.ClientRunner{}
			co.On("SubmitDeviceDecommisioningJob", context.Background(), mock.AnythingOfType("orchestrator.DecommissioningReq")).Return(
				tc.coSubmitDeviceDecommisioningJobErr)
			db := mstore.DataStore{}
			db.On("UpdateDevice", context.Background(),
				mock.AnythingOfType("model.Device"),
				mock.AnythingOfType("model.DeviceUpdate")).Return(
				tc.dbUpdateDeviceErr)
			db.On("DeleteAuthSetsForDevice", context.Background(), mock.AnythingOfType("string")).Return(
				tc.dbDeleteAuthSetsForDeviceErr)
			db.On("DeleteTokenByDevId", context.Background(), mock.AnythingOfType("string")).Return(
				tc.dbDeleteTokenByDevIdErr)
			db.On("DeleteDevice", context.Background(), mock.AnythingOfType("string")).Return(
				tc.dbDeleteDeviceErr)

			devauth := NewDevAuth(&db, nil, nil, &co, nil, Config{})
			err := devauth.DecommissionDevice(context.Background(), "devId")

			if tc.outErr != "" {
				assert.EqualError(t, err, tc.outErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
