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
	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/deviceauth/utils"
	"github.com/pkg/errors"
	"time"
)

var (
	ErrDevAuthUnauthorized = errors.New("dev auth: unauthorized")
	ErrDevAuthInternal     = errors.New("dev auth: internal error")
)

// TODO:
// Expiration Timeout should be moved to database
// Do we need Expiration Timeout per device?
const (
	defaultExpirationTimeout = 3600
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
	VerifyToken(token string) error
}

type DevAuth struct {
	db  DataStore
	c   DevAdmClientI
	jwt JWTAgentApp
	log *log.Logger
}

func NewDevAuth(d DataStore, c DevAdmClientI, jwt JWTAgentApp) DevAuthApp {
	return &DevAuth{db: d,
		c:   c,
		jwt: jwt,
		log: log.New("devauth")}
}

func (d *DevAuth) SubmitAuthRequest(r *AuthReq) (string, error) {
	id := utils.CreateDevId(r.IdData)

	//check if device exists with the same id+key
	//TODO at some point add key rotation handling (same id, different key)
	dev, err := d.findMatchingDevice(id, r.PubKey)
	if err != nil {
		d.log.Errorf("find matching device error: %v", err)

		return "", err
	}

	//for existing devices - check auth reqs seq_no
	if dev != nil {
		err = d.verifySeqNo(id, r.SeqNo)
		if err != nil {
			d.log.Errorf("verify seq no error: %v", err)
			return "", err
		}
	} else {
		//new device - create in 'pending' state
		dev = NewDevice(id, r.IdData, r.PubKey, r.TenantToken)

		if err := d.db.AddDevice(dev); err != nil {
			d.log.Errorf("db add device error: %v", err)
			return "", ErrDevAuthInternal
		}

		if err := d.c.AddDevice(dev); err != nil {
			d.log.Errorf("devadm add device error: %v", err)
			return "", ErrDevAuthInternal
		}
	}

	//save auth req
	r.Timestamp = time.Now()
	r.DeviceId = id
	r.Status = dev.Status
	err = d.db.AddAuthReq(r)
	if err != nil {
		d.log.Errorf("db add auth req error: %v", err)
		return "", ErrDevAuthInternal
	}

	//return according to dev status
	if dev.Status == DevStatusAccepted {
		token, err := d.jwt.GenerateTokenSignRS256(id)
		if err != nil {
			return "", ErrDevAuthInternal
		}

		if err := d.db.AddToken(token); err != nil {
			return "", ErrDevAuthInternal
		}
		return token.Token, nil
	} else {
		return "", ErrDevAuthUnauthorized
	}
}

// try to get an existing device, while checking for mismatched pubkey/id pairs
func (d *DevAuth) findMatchingDevice(id, key string) (*Device, error) {
	//find devs by id and key, compare results
	devi, err := d.db.GetDeviceById(id)
	if err != nil && err != ErrDevNotFound {
		d.log.Errorf("db get device by id error: %v", err)
		return nil, ErrDevAuthInternal
	}

	devk, err := d.db.GetDeviceByKey(key)
	if err != nil && err != ErrDevNotFound {
		d.log.Errorf("db get device by key error: %v", err)
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
		d.log.Errorf("db get auth requests error: %v", err)
		return ErrDevAuthInternal
	}

	if r != nil {
		if seq_no <= r[0].SeqNo {
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
		d.log.Errorf("db update device error: %v", err)
		return ErrDevAuthInternal
	}

	return nil
}

func (d *DevAuth) RejectDevice(dev_id string) error {
	// delete device token
	err := d.db.DeleteTokenByDevId(dev_id)
	if err != nil && err != ErrTokenNotFound {
		d.log.Errorf("db delete device token error: %v", err)
		return ErrDevAuthInternal
	}

	// update device status
	updev := &Device{Id: dev_id, Status: DevStatusRejected}

	if err := d.db.UpdateDevice(updev); err != nil {
		d.log.Errorf("db update device error: %v", err)
		return ErrDevAuthInternal
	}

	return nil
}

func (*DevAuth) GetDeviceToken(dev_id string) (*Token, error) {
	return nil, errors.New("not implemented")
}

func (d *DevAuth) RevokeToken(token_id string) error {
	d.log.Warnf("Revoke token with jti: %s", token_id)
	return d.db.DeleteToken(token_id)
}

func (d *DevAuth) VerifyToken(token string) error {
	// validate signature and claims
	jti, err := d.jwt.ValidateTokenSignRS256(token)
	if err != nil {
		if err == ErrTokenExpired {
			d.log.Errorf("Token %s expired: %v", jti, err)
			err := d.db.DeleteToken(jti)
			if err == ErrTokenNotFound {
				d.log.Errorf("Token with jti: %s not found", jti)
				return err
			}
			if err != nil {
				d.log.Errorf("Cannot delete token with jti: %s : %s", jti, err)
				return ErrDevAuthInternal
			}
			return ErrTokenExpired
		}
		d.log.Errorf("Token invalid: %v", err)
		return ErrTokenInvalid
	}
	// check if token is in the system
	_, err = d.db.GetToken(jti)
	if err == ErrTokenNotFound {
		d.log.Errorf("Token with jti: %s not found", jti)
		return err
	}
	if err != nil {
		d.log.Errorf("Cannot get token with id: %s from database: %s", jti, err)
		return ErrDevAuthInternal
	}
	return nil
}
