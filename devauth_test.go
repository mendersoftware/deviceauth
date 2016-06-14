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
	"github.com/stretchr/testify/assert"
	"testing"
)

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

			getAuthReqsSeqNo: 125,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

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

			getAuthReqsSeqNo: 125,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

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

			getAuthReqsSeqNo: 125,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

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

			getAuthReqsSeqNo: 125,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

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

			getAuthReqsSeqNo: 125,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

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

			getAuthReqsSeqNo: 122,
			getAuthReqsErr:   nil,

			addDeviceErr:  nil,
			addAuthReqErr: nil,

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

			res: "",
			err: ErrDevAuthUnauthorized,
		},
	}

	for _, tc := range testCases {
		db := MockDataStore{
			mockGetAuthRequests: func(device_id string, skip, limit int) ([]AuthReq, error) {
				if tc.getAuthReqsErr != nil {
					return nil, tc.getAuthReqsErr
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
		}

		devauth := NewDevAuth(&db)
		res, err := devauth.SubmitAuthRequest(&req)

		assert.Equal(t, tc.res, res)
		assert.Equal(t, tc.err, err)
	}
}

func TestAcceptDevice(t *testing.T) {
	testCases := []struct {
		dbErr string
	}{
		{
			dbErr: "",
		},
		{
			dbErr: "failed to update device",
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
		}

		devauth := NewDevAuth(&db)
		err := devauth.AcceptDevice("dummyid")

		if tc.dbErr != "" {
			assert.Equal(t, ErrDevAuthInternal, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestRejectDevice(t *testing.T) {
	testCases := []struct {
		dbErr string
	}{
		{
			dbErr: "",
		},
		{
			dbErr: "failed to update device",
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
		}

		devauth := NewDevAuth(&db)
		err := devauth.RejectDevice("dummyid")

		if tc.dbErr != "" {
			assert.Equal(t, ErrDevAuthInternal, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
