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
	"net/http"

	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/deviceauth/requestid"
	"github.com/mendersoftware/deviceauth/utils"
	"github.com/pkg/errors"
)

var (
	ErrDevAuthUnauthorized  = errors.New("dev auth: unauthorized")
	ErrDevAuthKeyMismatch   = errors.New("dev auth: device key mismatch")
	ErrDevAuthIdKeyMismatch = errors.New("dev auth: ID and key mismatch")
)

// Expiration Timeout should be moved to database
// Do we need Expiration Timeout per device?
const (
	defaultExpirationTimeout = 3600
)

// helper for obtaining API clients
type ApiClientGetter func() requestid.ApiRequester

func simpleApiClientGetter() requestid.ApiRequester {
	return &http.Client{}
}

// this device auth service interface
type DevAuthApp interface {
	SubmitAuthRequest(r *AuthReq) (string, error)

	GetDevices(skip, limit uint) ([]Device, error)
	GetDevice(dev_id string) (*Device, error)
	AcceptDevice(dev_id string) error
	RejectDevice(dev_id string) error
	ResetDevice(dev_id string) error
	GetDeviceToken(dev_id string) (*Token, error)

	RevokeToken(token_id string) error
	VerifyToken(token string) error
	WithContext(c *RequestContext) DevAuthApp

	log.ContextLogger
}

type DevAuth struct {
	db           DataStore
	cDevAdm      DevAdmClientI
	cInv         InventoryClientI
	jwt          JWTAgentApp
	log          *log.Logger
	clientGetter ApiClientGetter
}

func NewDevAuth(d DataStore, cda DevAdmClientI, ci InventoryClientI, jwt JWTAgentApp) DevAuthApp {
	return &DevAuth{
		db:           d,
		cDevAdm:      cda,
		cInv:         ci,
		jwt:          jwt,
		log:          log.New(log.Ctx{}),
		clientGetter: simpleApiClientGetter,
	}
}

func (d *DevAuth) SubmitAuthRequest(r *AuthReq) (string, error) {
	return d.SubmitAuthRequestWithClient(r, d.clientGetter())
}

func (d *DevAuth) SubmitAuthRequestWithClient(r *AuthReq, client requestid.ApiRequester) (string, error) {
	id := utils.CreateDevId(r.IdData)

	//check if device exists with the same id+key
	//TODO at some point add key rotation handling (same id, different key)
	dev, err := d.findMatchingDevice(id, r.PubKey)
	if err != nil {
		d.log.Errorf("find matching device error: %v", err)

		return "", err
	}

	if dev == nil {
		//new device - create in 'pending' state
		dev = NewDevice(id, r.IdData, r.PubKey, r.TenantToken)

		if err := d.cDevAdm.AddDevice(dev, client); err != nil {
			return "", errors.Wrap(err, "devadm add device error")
		}

		// add device to database only if it was
		// successfully added to admission service
		if err := d.db.AddDevice(dev); err != nil {
			return "", errors.Wrap(err, "db add device error")
		}

	}

	//return according to dev status
	if dev.Status == DevStatusAccepted {
		token, err := d.jwt.GenerateTokenSignRS256(id)
		if err != nil {
			return "", errors.Wrap(err, "generate token error")
		}

		if err := d.db.AddToken(token); err != nil {
			return "", errors.Wrap(err, "add token error")
		}

		return token.Token, nil
	}

	return "", ErrDevAuthUnauthorized
}

func (d *DevAuth) SubmitInventoryDevice(dev Device) error {
	return d.SubmitInventoryDeviceWithClient(dev, d.clientGetter())
}

func (d *DevAuth) SubmitInventoryDeviceWithClient(dev Device, client requestid.ApiRequester) error {
	err := d.cInv.AddDevice(&dev, client)
	if err != nil {
		return errors.Wrap(err, "failed to add device to inventory")
	}
	return nil
}

// try to get an existing device, while checking for mismatched pubkey/id pairs
func (d *DevAuth) findMatchingDevice(id, key string) (*Device, error) {
	//find devs by id and key, compare results
	devi, err := d.db.GetDeviceById(id)
	if err != nil && err != ErrDevNotFound {
		return nil, errors.Wrap(err, "db get device by id error")
	}

	devk, err := d.db.GetDeviceByKey(key)
	if err != nil && err != ErrDevNotFound {
		return nil, errors.Wrap(err, "db get device by key error")
	}

	//cases:
	//both devs nil - new device
	//both devs !nil - must compare id/key
	//other combinations: id/key mismatch
	if devi == nil && devk == nil {
		return nil, nil
	} else if devi != nil && devk != nil {
		if devi.Id != devk.Id {
			return nil, ErrDevAuthIdKeyMismatch
		}

		if devi.PubKey != devk.PubKey {
			return nil, ErrDevAuthKeyMismatch
		}

		return devi, nil
	}

	return nil, ErrDevAuthUnauthorized
}

func (d *DevAuth) GetDevices(skip, limit uint) ([]Device, error) {
	return d.db.GetDevices(skip, limit)
}

func (d *DevAuth) GetDevice(devId string) (*Device, error) {
	dev, err := d.db.GetDeviceById(devId)
	if err != nil && err != ErrDevNotFound {
		return nil, errors.Wrap(err, "db get device by id error")
	}
	return dev, err
}

func (d *DevAuth) AcceptDevice(dev_id string) error {
	updev := &Device{Id: dev_id, Status: DevStatusAccepted}

	if _, err := d.db.GetDeviceById(dev_id); err != nil {
		if err == ErrDevNotFound {
			return err
		}
		return errors.Wrap(err, "db get device error")
	}

	if err := d.SubmitInventoryDevice(*updev); err != nil {
		return errors.Wrap(err, "inventory device add error")
	}

	if err := d.db.UpdateDevice(updev); err != nil {
		return errors.Wrap(err, "db update device error")
	}

	return nil
}

func (d *DevAuth) RejectDevice(dev_id string) error {
	// delete device token
	err := d.db.DeleteTokenByDevId(dev_id)
	if err != nil && err != ErrTokenNotFound {
		return errors.Wrap(err, "db delete device token error")
	}

	// update device status
	updev := &Device{Id: dev_id, Status: DevStatusRejected}

	if err := d.db.UpdateDevice(updev); err != nil {
		return errors.Wrap(err, "db update device error")
	}

	return nil
}

func (d *DevAuth) ResetDevice(dev_id string) error {
	// delete device token
	err := d.db.DeleteTokenByDevId(dev_id)
	if err != nil && err != ErrTokenNotFound {
		return errors.Wrap(err, "db delete device token error")
	}

	// update device status
	updev := &Device{Id: dev_id, Status: DevStatusPending}

	if err := d.db.UpdateDevice(updev); err != nil {
		return errors.Wrap(err, "db update device error")
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
				return errors.Wrapf(err, "Cannot delete token with jti: %s : %s", jti, err)
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
		return errors.Wrapf(err, "Cannot get token with id: %s from database: %s", jti, err)
	}
	return nil
}

func (d *DevAuth) WithContext(ctx *RequestContext) DevAuthApp {
	dwc := &DevAuthWithContext{
		*d,
		ctx,
	}
	dwc.clientGetter = dwc.contextClientGetter
	return dwc
}

func (d *DevAuth) UseLog(l *log.Logger) {
	d.log = l.F(log.Ctx{})
}
