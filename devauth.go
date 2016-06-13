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
	"github.com/mendersoftware/deviceauth/utils"
	"github.com/pkg/errors"
	"time"
)

var (
	ErrDevAuthUnauthorized = errors.New("dev auth: unauthorized")
	ErrDevAuthInternal     = errors.New("dev auth: internal error")

	DevStatusAccepted = "accepted"
	DevStatusRejected = "rejected"
	DevStatusPending  = "pending"
)

// this device auth service interface
type DevAuthApp interface {
	SubmitAuthRequest(r *AuthReq) (string, error)
	GetAuthRequests(dev_id string) ([]AuthReq, error)

	GetDevices(skip, limit int, tenant_token, status string) ([]Device, error)
	GetDevice(dev_id string) (*Device, error)
	AcceptDevice(dev_id string) error
	RejectDevice(dev_id string) error
	GetDeviceToken(dev_id string) (*Token, error)

	RevokeToken(token_id string) error
	VerifyToken(token string) (bool, error)
}

type DevAuth struct {
	db DataStore
}

func NewDevAuth(d DataStore) DevAuthApp {
	return &DevAuth{db: d}
}

func (d *DevAuth) SubmitAuthRequest(r *AuthReq) (string, error) {
	id := utils.CreateDevId(r.IdData)

	//check if device exists with the same id+key
	dev, err := d.findMatchingDevice(id, r.PubKey)
	if err != nil {
		return "", err
	}

	//for existing devices - check auth reqs seq_no
	if dev != nil {
		err = d.verifySeqNo(id, r.SeqNo)
		if err != nil {
			return "", err
		}
	} else {
		//new device - create in 'pending' state
		dev = NewDevice(id, r.IdData, r.PubKey, r.TenantToken)
	}

	//save auth req
	r.Timestamp = time.Now()
	r.DeviceId = id
	r.Status = dev.Status
	err = d.db.AddAuthReq(r)
	if err != nil {
		//TODO log db err
		return "", ErrDevAuthInternal
	}

	//return according to dev status
	if dev.Status == DevStatusAccepted {
		return "dummytoken", nil
	} else {
		return "", ErrDevAuthUnauthorized
	}
}

// try to get an existing device, while checking for mismatched pubkey/id pairs
func (d *DevAuth) findMatchingDevice(id, key string) (*Device, error) {
	//find devs by id and key, compare results
	devi, err := d.db.GetDeviceById(id)
	if err != nil && err != ErrDevNotFound {
		//TODO log db err
		return nil, ErrDevAuthInternal
	}

	devk, err := d.db.GetDeviceByKey(key)
	if err != nil && err != ErrDevNotFound {
		//TODO log db err
		return nil, ErrDevAuthInternal
	}

	//cases:
	//both devs nil - new device
	//both devs !nil - must compare id/key
	//other combinations: id/key mismatch
	if devi == nil && devk == nil {
		return nil, nil
	} else if devi != nil && devk != nil {
		if devi.Id == devk.Id &&
			devi.PubKey == devk.PubKey {
			return devi, nil
		}
	}

	return nil, ErrDevAuthUnauthorized
}

// check seq_no against the latest auth req of this device
func (d *DevAuth) verifySeqNo(dev_id string, seq_no uint64) error {
	r, err := d.db.GetAuthRequests(dev_id, 0, 1)
	if err != nil {
		//TODO log db err
		return ErrDevAuthInternal
	}

	if r != nil {
		if seq_no >= r[0].SeqNo {
			return ErrDevAuthUnauthorized
		}
	}

	return nil
}

func (*DevAuth) GetAuthRequests(dev_id string) ([]AuthReq, error) {
	return nil, errors.New("not implemented")
}

func (*DevAuth) GetDevices(skip, limit int, tenant_token, status string) ([]Device, error) {
	return nil, errors.New("not implemented")
}

func (*DevAuth) GetDevice(dev_id string) (*Device, error) {
	return nil, errors.New("not implemented")
}

func (d *DevAuth) AcceptDevice(dev_id string) error {
	updev := &Device{Id: dev_id, Status: DevStatusAccepted}

	if err := d.db.UpdateDevice(updev); err != nil {
		//TODO log db err
		return ErrDevAuthInternal
	}

	return nil
}

func (d *DevAuth) RejectDevice(dev_id string) error {
	updev := &Device{Id: dev_id, Status: DevStatusRejected}

	if err := d.db.UpdateDevice(updev); err != nil {
		//TODO log db err
		return ErrDevAuthInternal
	}

	return nil
}

func (*DevAuth) GetDeviceToken(dev_id string) (*Token, error) {
	return nil, errors.New("not implemented")
}

func (*DevAuth) RevokeToken(token_id string) error {
	return errors.New("not implemented")
}

func (*DevAuth) VerifyToken(token string) (bool, error) {
	return false, errors.New("not implemented")
}
