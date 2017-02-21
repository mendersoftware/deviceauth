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
	"testing"

	"github.com/mendersoftware/deviceauth/requestid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSubmitAuthRequest(t *testing.T) {
	req := AuthReq{
		IdData:      "iddata",
		TenantToken: "tenant",
		PubKey:      "pubkey",
	}

	//precomputed device id for "iddata"
	devId := "a8f728bad9540212e93283282a07b774f9bd85a5d550faa9b2afe1502cdc6328"

	testCases := []struct {
		inReq AuthReq

		devStatus string

		// key of returned device
		getDevByIdKey string
		getDevByIdErr error

		//id of returned device
		getDevByKeyId  string
		getDevByKeyErr error

		getAuthReqsErr error

		addDeviceErr  error
		addAuthReqErr error

		devAdmErr error

		res string
		err error
	}{
		{
			//existing, accepted device
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "pubkey",
			getDevByIdErr: nil,

			getDevByKeyId:  devId,
			getDevByKeyErr: nil,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "dummytoken",
			err: nil,
		},
		{
			//existing, rejected device
			inReq: req,

			devStatus: DevStatusRejected,

			getDevByIdKey: "pubkey",
			getDevByIdErr: nil,

			getDevByKeyId:  devId,
			getDevByKeyErr: nil,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
		{
			//existing, pending device
			inReq: req,

			devStatus: DevStatusPending,

			getDevByIdKey: "pubkey",
			getDevByIdErr: nil,

			getDevByKeyId:  devId,
			getDevByKeyErr: nil,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
		{
			//existing device, key duplicate + id mismatch
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "pubkey",
			getDevByIdErr: nil,

			getDevByKeyId:  "anotherid",
			getDevByKeyErr: nil,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthIdKeyMismatch,
		},
		{
			//existing device, id duplicate + key mismatch
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "anotherkey",
			getDevByIdErr: nil,

			getDevByKeyId:  devId,
			getDevByKeyErr: nil,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthKeyMismatch,
		},
		{
			//new device
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "",
			getDevByIdErr: ErrDevNotFound,

			getDevByKeyId:  "",
			getDevByKeyErr: ErrDevNotFound,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
		{
			//new device - admission error
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "",
			getDevByIdErr: ErrDevNotFound,

			getDevByKeyId:  "",
			getDevByKeyErr: ErrDevNotFound,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: errors.New("failed to add device"),

			res: "",
			err: errors.New("devadm add device error: failed to add device"),
		},
		{
			//device exists in DB but has not sent any requests yet?
			inReq: req,

			devStatus: DevStatusPending,

			getDevByIdKey: "pubkey",
			getDevByIdErr: nil,

			getDevByKeyId:  devId,
			getDevByKeyErr: nil,

			getAuthReqsErr: nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
	}

	for tcidx, tc := range testCases {
		t.Logf("tc: %d", tcidx)

		db := MockDataStore{}
		db.On("GetDeviceById", mock.AnythingOfType("string")).Return(
			func(id string) *Device {
				if tc.getDevByIdErr == nil {
					return &Device{
						PubKey: tc.getDevByIdKey,
						Id:     id,
						Status: tc.devStatus,
					}
				}
				return nil
			},
			tc.getDevByIdErr)

		db.On("GetDeviceByKey", mock.AnythingOfType("string")).Return(
			func(key string) *Device {
				if tc.getDevByKeyErr == nil {
					return &Device{
						Id:     tc.getDevByKeyId,
						PubKey: key,
						Status: tc.devStatus,
					}
				}
				return nil
			},
			tc.getDevByKeyErr)

		db.On("AddDevice", mock.AnythingOfType("*main.Device")).Return(tc.addDeviceErr)
		db.On("AddToken", mock.AnythingOfType("*main.Token")).Return(nil)
		db.On("GetToken", mock.AnythingOfType("string")).Return(nil, nil)
		db.On("DeleteToken", mock.AnythingOfType("string")).Return(nil)
		db.On("DeleteToken", mock.AnythingOfType("string")).Return(nil)
		db.On("DeleteTokenByDevId", mock.AnythingOfType("string")).Return(nil)

		cda := MockDevAdmClient{}
		cda.On("AddDevice", mock.AnythingOfType("*main.Device"),
			mock.MatchedBy(func(_ requestid.ApiRequester) bool { return true })).
			Return(tc.devAdmErr)

		cdi := MockInventoryClient{}
		cdi.On("AddDevice", mock.AnythingOfType("*main.Device"),
			mock.MatchedBy(func(_ requestid.ApiRequester) bool { return true })).
			Return(tc.devAdmErr)

		jwt := MockJWTAgent{
			mockGenerateTokenSignRS256: func(devId string) (*Token, error) {
				return NewToken("", devId, "dummytoken"), nil
			},
			mockValidateTokenSignRS256: func(token string) (string, error) {
				return "", nil
			},
		}

		devauth := NewDevAuth(&db, &cda, &cdi, &jwt)
		res, err := devauth.SubmitAuthRequest(&req)

		assert.Equal(t, tc.res, res)
		if tc.err != nil {
			assert.EqualError(t, err, tc.err.Error())
		}
	}
}

func TestAcceptDevice(t *testing.T) {
	testCases := []struct {
		dbUpdateErr error
		dbGetErr    error
		invErr      error

		outErr string
	}{
		{},
		{
			dbGetErr: ErrDevNotFound,
			outErr:   ErrDevNotFound.Error(),
		},
		{
			dbUpdateErr: errors.New("failed to update device"),
			outErr:      "db update device error: failed to update device",
		},
		{
			invErr: errors.New("inventory failed"),
			outErr: "inventory device add error: failed to add device to inventory: inventory failed",
		},
	}

	for idx, tc := range testCases {
		t.Logf("running %v", idx)
		db := MockDataStore{}
		db.On("UpdateDevice", mock.AnythingOfType("*main.Device")).Return(tc.dbUpdateErr)

		if tc.dbGetErr != nil {
			db.On("GetDeviceById", mock.AnythingOfType("string")).Return(nil, tc.dbGetErr)
		} else {
			db.On("GetDeviceById", mock.AnythingOfType("string")).Return(
				func(id string) *Device {
					return &Device{
						Id:     id,
						Status: "pending",
					}
				},
				nil)
		}

		inv := MockInventoryClient{}
		inv.On("AddDevice", mock.AnythingOfType("*main.Device"),
			mock.MatchedBy(func(_ requestid.ApiRequester) bool { return true })).
			Return(tc.invErr)

		devauth := NewDevAuth(&db, nil, &inv, nil)
		err := devauth.AcceptDevice("dummyid")

		if tc.outErr != "" {
			assert.EqualError(t, err, tc.outErr)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestRejectDevice(t *testing.T) {
	testCases := []struct {
		dbErr            string
		dbDelDevTokenErr error

		outErr string
	}{
		{
			dbErr:            "",
			dbDelDevTokenErr: nil,
		},
		{
			dbErr:            "failed to update device",
			dbDelDevTokenErr: nil,
			outErr:           "db update device error: failed to update device",
		},
		{
			dbErr:            "",
			dbDelDevTokenErr: ErrTokenNotFound,
			outErr:           "db delete device token error: token not found",
		},
		{
			dbErr:            "",
			dbDelDevTokenErr: errors.New("some error"),
			outErr:           "db delete device token error: some error",
		},
	}

	for _, tc := range testCases {
		db := MockDataStore{}
		db.On("UpdateDevice", mock.AnythingOfType("*main.Device")).Return(
			func(d *Device) error {
				if tc.dbErr != "" {
					return errors.New(tc.dbErr)
				}

				return nil
			})
		db.On("DeleteTokenByDevId", mock.AnythingOfType("string")).Return(
			tc.dbDelDevTokenErr)

		devauth := NewDevAuth(&db, nil, nil, nil)
		err := devauth.RejectDevice("dummyid")

		if tc.dbErr != "" || (tc.dbDelDevTokenErr != nil && tc.dbDelDevTokenErr != ErrTokenNotFound) {
			assert.EqualError(t, err, tc.outErr)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestResetDevice(t *testing.T) {
	testCases := []struct {
		dbErr            string
		dbDelDevTokenErr error

		outErr string
	}{
		{
			dbErr:            "",
			dbDelDevTokenErr: nil,
		},
		{
			dbErr:            "failed to update device",
			dbDelDevTokenErr: nil,
			outErr:           "db update device error: failed to update device",
		},
		{
			dbErr:            "",
			dbDelDevTokenErr: ErrTokenNotFound,
			outErr:           "db delete device token error: token not found",
		},
		{
			dbErr:            "",
			dbDelDevTokenErr: errors.New("some error"),
			outErr:           "db delete device token error: some error",
		},
	}

	for _, tc := range testCases {
		db := MockDataStore{}
		db.On("UpdateDevice", mock.AnythingOfType("*main.Device")).Return(
			func(d *Device) error {
				if tc.dbErr != "" {
					return errors.New(tc.dbErr)
				}

				return nil
			})
		db.On("DeleteTokenByDevId", mock.AnythingOfType("string")).Return(
			tc.dbDelDevTokenErr)

		devauth := NewDevAuth(&db, nil, nil, nil)
		err := devauth.ResetDevice("dummyid")

		if tc.dbErr != "" || (tc.dbDelDevTokenErr != nil && tc.dbDelDevTokenErr != ErrTokenNotFound) {
			assert.EqualError(t, err, tc.outErr)
		} else {
			assert.NoError(t, err)
		}
	}
}
