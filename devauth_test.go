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
	"github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/deviceauth/requestid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetDevAuth(t *testing.T) {
	//this will ping the db, so it;s a 'long' test
	if testing.Short() {
		t.Skip("skipping TestGetDevAuth in short mode.")
	}

	// GetDevAuth will initialize data store that tries to connect to a DB
	// specified in configuration. Since we are using dbtest, an on demand DB will
	// be started. However we still need to figure out the address the test
	// instance is listening on, so that we can set it in DevAuth configuration.
	// configuration.
	session := db.Session()
	defer session.Close()
	dbs := session.LiveServers()
	assert.Len(t, dbs, 1)

	dbaddr := dbs[0]
	t.Logf("test db address: %s", dbaddr)

	config.SetDefaults(config.Config, configDefaults)
	config.Config.Set(SettingDb, dbaddr)
	config.Config.Set(SettingServerPrivKeyPath, "testdata/private.pem")
	d, err := GetDevAuth(config.Config, log.New(log.Ctx{}))
	// we expect the test to fail as there's no locally running DB
	assert.NoError(t, err)
	assert.NotNil(t, d)

	// cleanup DB session
	da, _ := d.(*DevAuth)
	mdb, _ := da.db.(*DataStoreMongo)
	mdb.session.Close()
}

func TestSubmitAuthRequest(t *testing.T) {
	req := AuthReq{
		IdData:      "iddata",
		TenantToken: "tenant",
		PubKey:      "pubkey",
		SeqNo:       123,
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

		getAuthReqsSeqNo uint64
		getAuthReqsErr   error

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

			getAuthReqsSeqNo: 122,
			getAuthReqsErr:   nil,

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

			getAuthReqsSeqNo: 122,
			getAuthReqsErr:   nil,

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

			getAuthReqsSeqNo: 122,
			getAuthReqsErr:   nil,

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

			getAuthReqsSeqNo: 122,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
		{
			//existing device, id duplicate + key mismatch
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "anotherkey",
			getDevByIdErr: nil,

			getDevByKeyId:  devId,
			getDevByKeyErr: nil,

			getAuthReqsSeqNo: 122,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
		{
			//existing, accepted device, but wrong seq_no
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "pubkey",
			getDevByIdErr: nil,

			getDevByKeyId:  devId,
			getDevByKeyErr: nil,

			getAuthReqsSeqNo: 124,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
		{
			//new device
			inReq: req,

			devStatus: DevStatusAccepted,

			getDevByIdKey: "",
			getDevByIdErr: ErrDevNotFound,

			getDevByKeyId:  "",
			getDevByKeyErr: ErrDevNotFound,

			getAuthReqsSeqNo: 125,
			getAuthReqsErr:   nil,

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

			getAuthReqsSeqNo: 122,
			getAuthReqsErr:   nil,

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

			getAuthReqsSeqNo: 0, // invoke nil case
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

			devAdmErr: nil,

			res: "",
			err: ErrDevAuthUnauthorized,
		},
	}

	for tcidx, tc := range testCases {
		t.Logf("tc: %d", tcidx)

		db := MockDataStore{
			mockGetAuthRequests: func(device_id string, skip, limit int) ([]AuthReq, error) {
				if tc.getAuthReqsErr != nil {
					return nil, tc.getAuthReqsErr
				}

				if tc.getAuthReqsSeqNo == 0 {
					// trigger empty slice
					return []AuthReq{}, nil
				}
				return []AuthReq{AuthReq{SeqNo: tc.getAuthReqsSeqNo}}, nil
			},

			mockGetDeviceById: func(id string) (*Device, error) {
				if tc.getDevByIdErr != nil {
					return nil, tc.getDevByIdErr
				}
				return &Device{PubKey: tc.getDevByIdKey,
					Id:     devId,
					Status: tc.devStatus}, nil
			},

			mockGetDeviceByKey: func(key string) (*Device, error) {
				if tc.getDevByKeyErr != nil {
					return nil, tc.getDevByKeyErr
				}
				return &Device{Id: tc.getDevByKeyId,
					PubKey: key,
					Status: tc.devStatus}, nil
			},

			mockAddAuthReq: func(r *AuthReq) error {
				return tc.addAuthReqErr
			},

			mockAddDevice: func(d *Device) error {
				return tc.addDeviceErr
			},

			mockAddToken: func(t *Token) error {
				return nil
			},

			mockGetToken: func(jti string) (*Token, error) {
				return nil, nil
			},

			mockDeleteToken: func(jti string) error {
				return nil
			},

			mockDeleteTokenByDevId: func(dev_id string) error {
				return nil
			},
		}

		cda := MockDevAdmClient{
			mockAddDevice: func(dev *Device, c requestid.ApiRequester) error {
				return tc.devAdmErr
			},
		}

		cdi := MockInventoryClient{
			mockAddDevice: func(dev *Device, c requestid.ApiRequester) error {
				return tc.devAdmErr
			},
		}

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
		db := MockDataStore{
			mockUpdateDevice: func(d *Device) error {
				if tc.dbUpdateErr != nil {
					return tc.dbUpdateErr
				}

				return nil
			},
			mockGetDeviceById: func(id string) (*Device, error) {
				if tc.dbGetErr != nil {
					return nil, tc.dbGetErr
				}

				return &Device{Id: id, Status: "pending"}, nil
			},
		}

		inv := MockInventoryClient{
			mockAddDevice: func(d *Device, client requestid.ApiRequester) error {
				if tc.invErr != nil {
					return tc.invErr
				}
				return nil
			},
		}

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
		db := MockDataStore{
			mockUpdateDevice: func(d *Device) error {
				if tc.dbErr != "" {
					return errors.New(tc.dbErr)
				}

				return nil
			},
			mockDeleteTokenByDevId: func(dev_id string) error {
				return tc.dbDelDevTokenErr
			},
		}

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
		db := MockDataStore{
			mockUpdateDevice: func(d *Device) error {
				if tc.dbErr != "" {
					return errors.New(tc.dbErr)
				}

				return nil
			},
			mockDeleteTokenByDevId: func(dev_id string) error {
				return tc.dbDelDevTokenErr
			},
		}

		devauth := NewDevAuth(&db, nil, nil, nil)
		err := devauth.ResetDevice("dummyid")

		if tc.dbErr != "" || (tc.dbDelDevTokenErr != nil && tc.dbDelDevTokenErr != ErrTokenNotFound) {
			assert.EqualError(t, err, tc.outErr)
		} else {
			assert.NoError(t, err)
		}
	}
}
