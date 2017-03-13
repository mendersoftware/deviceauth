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
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDevAuthSubmitAuthRequest(t *testing.T) {
	t.Parallel()

	pubKey := "dummy_pubkey"
	idData := "dummy_iddata"
	devId := "dummy_devid"
	authId := "dummy_aid"

	req := AuthReq{
		IdData:      idData,
		TenantToken: "tenant",
		PubKey:      pubKey,
	}

	testCases := []struct {
		inReq AuthReq

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

		res string
		err error
	}{
		{
			// pretend we failed to add device to DB
			inReq:        req,
			addDeviceErr: errors.New("failed"),
			err:          errors.New("failed"),
		},
		{
			//existing device, existing auth set, auth set accepted,
			//admission was notified, so we should get a token right
			//away
			inReq: req,

			addDeviceErr:  ErrObjectExists,
			addAuthSetErr: ErrObjectExists,

			devStatus:     DevStatusAccepted,
			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			admissionNotified: true,

			res: "dummytoken",
		},
		{
			//existing device, existing auth set, auth set rejected,
			//no token
			inReq: req,

			addDeviceErr:  ErrObjectExists,
			addAuthSetErr: ErrObjectExists,

			devStatus:     DevStatusRejected,
			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			admissionNotified: true,

			err: ErrDevAuthUnauthorized,
		},
		{
			//existing, pending device
			inReq: req,

			addDeviceErr:  ErrObjectExists,
			addAuthSetErr: ErrObjectExists,

			devStatus:     DevStatusPending,
			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			admissionNotified: true,

			err: ErrDevAuthUnauthorized,
		},
		{
			//new device
			inReq: req,

			devStatus: DevStatusPending,

			getDevByIdKey: pubKey,
			getDevByKeyId: devId,

			err: ErrDevAuthUnauthorized,
		},
		{
			//known device, adding returns that device exists, but
			//trying to fetch it fails
			inReq: req,

			addDeviceErr: ErrObjectExists,

			getDevByIdErr: ErrDevNotFound,

			err: errors.New("failed to locate device"),
		},
		{
			//known device and auth set, but fetching auth set fails
			inReq: req,

			addDeviceErr:  ErrObjectExists,
			addAuthSetErr: ErrObjectExists,

			getAuthSetErr: ErrDevNotFound,

			err: errors.New("failed to locate device auth set"),
		},
		{
			//new device - admission error
			inReq: req,

			getDevByKeyId: devId,
			devAdmErr:     errors.New("failed to add device"),

			err: errors.New("devadm add device error: failed to add device"),
		},
	}

	for tcidx := range testCases {
		tc := testCases[tcidx]
		t.Run(fmt.Sprintf("tc: %d", tcidx), func(t *testing.T) {
			t.Parallel()

			db := MockDataStore{}
			db.On("AddDevice",
				mock.MatchedBy(
					func(d Device) bool {
						return d.IdData == idData
					})).Return(tc.addDeviceErr)

			db.On("GetDeviceByIdentityData", idData).Return(
				func(idata string) *Device {
					if tc.getDevByIdErr == nil {
						return &Device{
							PubKey: tc.getDevByIdKey,
							IdData: idata,
							Id:     devId,
						}
					}
					return nil
				},
				tc.getDevByIdErr)
			db.On("AddAuthSet",
				mock.MatchedBy(
					func(m AuthSet) bool {
						return m.DeviceId == devId
					})).Return(tc.addAuthSetErr)
			db.On("UpdateAuthSet",
				mock.MatchedBy(
					func(m AuthSet) bool {
						return m.DeviceId == devId

					}),
				mock.MatchedBy(
					func(m AuthSetUpdate) bool {
						return to.Bool(m.AdmissionNotified) == true
					})).Return(nil)

			db.On("GetAuthSetByDataKey",
				idData, pubKey).Return(
				func(idata string, key string) *AuthSet {
					if tc.getAuthSetErr == nil {
						return &AuthSet{
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
				mock.AnythingOfType("main.Token")).Return(nil)

			cda := MockDevAdmClient{}
			if !tc.admissionNotified {
				// setup admission client mock only if admission
				// was not notified yet as per test case
				cda.On("AddDevice",
					mock.MatchedBy(func(d *Device) bool { return d.Id == devId }),
					mock.MatchedBy(func(a *AuthSet) bool {
						return (a.Id == authId) &&
							(a.IdData == idData) &&
							(a.DeviceId == devId) &&
							(a.PubKey == pubKey)
					}),
					mock.MatchedBy(func(_ requestid.ApiRequester) bool { return true })).
					Return(tc.devAdmErr)
			}

			cdi := MockInventoryClient{}

			jwt := MockJWTAgentApp{}
			jwt.On("GenerateTokenSignRS256", mock.AnythingOfType("string")).Return(
				func(devid string) *Token {
					return NewToken("", devId, "dummytoken")
				}, nil)

			devauth := NewDevAuth(&db, &cda, &cdi, &jwt)
			res, err := devauth.SubmitAuthRequest(&req)

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
		aset        *AuthSet
		dbUpdateErr error
		dbGetErr    error
		invErr      error

		outErr string
	}{
		{
			aset: &AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
		},
		{
			dbGetErr: ErrDevNotFound,
			outErr:   ErrDevNotFound.Error(),
		},
		{
			aset: &AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbUpdateErr: errors.New("failed to update device"),
			outErr:      "db update device auth set error: failed to update device",
		},
		{
			aset: &AuthSet{
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

			db := MockDataStore{}
			db.On("GetAuthSetById", "dummy_aid").Return(tc.aset, tc.dbGetErr)
			if tc.aset != nil {
				db.On("UpdateAuthSet", *tc.aset,
					AuthSetUpdate{Status: DevStatusAccepted}).Return(tc.dbUpdateErr)
			}

			inv := MockInventoryClient{}
			inv.On("AddDevice", &Device{Id: "dummy_devid"},
				mock.MatchedBy(func(_ requestid.ApiRequester) bool { return true })).
				Return(tc.invErr)

			devauth := NewDevAuth(&db, nil, &inv, nil)
			err := devauth.AcceptDeviceAuth("dummy_devid", "dummy_aid")

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
		aset             *AuthSet
		dbErr            error
		dbDelDevTokenErr error

		outErr string
	}{
		{
			aset: &AuthSet{
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
			aset: &AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbDelDevTokenErr: ErrTokenNotFound,
			outErr:           "db delete device token error: token not found",
		},
		{
			aset: &AuthSet{
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

			db := MockDataStore{}
			db.On("GetAuthSetById", "dummy_aid").Return(tc.aset, tc.dbErr)
			if tc.aset != nil {
				db.On("UpdateAuthSet", *tc.aset,
					AuthSetUpdate{Status: DevStatusRejected}).Return(nil)
			}
			db.On("DeleteTokenByDevId", "dummy_devid").Return(
				tc.dbDelDevTokenErr)

			devauth := NewDevAuth(&db, nil, nil, nil)
			err := devauth.RejectDeviceAuth("dummy_devid", "dummy_aid")

			if tc.dbErr != nil || (tc.dbDelDevTokenErr != nil &&
				tc.dbDelDevTokenErr != ErrTokenNotFound) {

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
		aset             *AuthSet
		dbErr            error
		dbDelDevTokenErr error

		outErr string
	}{
		{
			aset: &AuthSet{
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
			aset: &AuthSet{
				Id:       "dummy_aid",
				DeviceId: "dummy_devid",
			},
			dbDelDevTokenErr: ErrTokenNotFound,
			outErr:           "db delete device token error: token not found",
		},
		{
			aset: &AuthSet{
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

			db := MockDataStore{}
			db.On("GetAuthSetById", "dummy_aid").Return(tc.aset, tc.dbErr)
			if tc.aset != nil {
				db.On("UpdateAuthSet", *tc.aset,
					AuthSetUpdate{Status: DevStatusPending}).Return(nil)
			}
			db.On("DeleteTokenByDevId", "dummy_devid").Return(
				tc.dbDelDevTokenErr)

			devauth := NewDevAuth(&db, nil, nil, nil)
			err := devauth.ResetDeviceAuth("dummy_devid", "dummy_aid")

			if tc.dbErr != nil ||
				(tc.dbDelDevTokenErr != nil &&
					tc.dbDelDevTokenErr != ErrTokenNotFound) {

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

		jti         string
		validateErr error

		token       *Token
		getTokenErr error

		auth       *AuthSet
		getAuthErr error
	}{
		{
			tokenString:      "expired",
			tokenValidateErr: ErrTokenExpired,

			jti:         "expired",
			validateErr: ErrTokenExpired,
		},
		{
			tokenString:      "bad",
			tokenValidateErr: ErrTokenInvalid,

			jti:         "bad",
			validateErr: ErrTokenInvalid,
		},
		{
			tokenString:      "good-no-auth",
			tokenValidateErr: ErrDevNotFound,

			jti: "good-no-auth",
			token: &Token{
				Id:        "good-no-auth",
				AuthSetId: "not-found",
			},
			getAuthErr: ErrDevNotFound,
		},
		{
			tokenString: "good-accepted",
			jti:         "good-accepted",
			token: &Token{
				Id:        "good-accepted",
				AuthSetId: "foo",
			},
			auth: &AuthSet{
				Id:     "foo",
				Status: DevStatusAccepted,
			},
		},
		{
			tokenString:      "good-rejected",
			tokenValidateErr: ErrTokenInvalid,

			jti: "good-rejected",
			token: &Token{
				Id:        "good-rejected",
				AuthSetId: "foo",
			},
			auth: &AuthSet{
				Id:     "foo",
				Status: DevStatusRejected,
			},
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %s", tc.tokenString), func(t *testing.T) {
			t.Parallel()

			db := &MockDataStore{}
			jwt := &MockJWTAgentApp{}

			devauth := NewDevAuth(db, nil, nil, jwt)

			jwt.On("ValidateTokenSignRS256", tc.tokenString).Return(tc.jti, tc.validateErr)

			if tc.validateErr == ErrTokenExpired {
				db.On("DeleteToken", tc.jti).Return(nil)
			}

			db.On("GetToken", tc.jti).Return(tc.token, tc.getTokenErr)

			if tc.token != nil {
				db.On("GetAuthSetById", tc.token.AuthSetId).Return(tc.auth, tc.getAuthErr)
			}

			err := devauth.VerifyToken(tc.tokenString)
			if tc.tokenValidateErr != nil {
				assert.EqualError(t, err, tc.tokenValidateErr.Error())
			} else {
				assert.NoError(t, err)
			}

		})
	}
}
