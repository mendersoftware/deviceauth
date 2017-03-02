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

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
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
	cDevAdm      DevAdmClient
	cInv         InventoryClient
	jwt          JWTAgentApp
	log          *log.Logger
	clientGetter ApiClientGetter
}

func NewDevAuth(d DataStore, cda DevAdmClient, ci InventoryClient, jwt JWTAgentApp) DevAuthApp {
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

	dev := NewDevice("", r.IdData, r.PubKey, r.TenantToken)

	// record device
	err := d.db.AddDevice(dev)
	if err != nil && err != ErrObjectExists {
		d.log.Errorf("failed to add/find device: %v", err)
		return "", err
	}
	// either the device was added or it was already present, in any case,
	// pull it from DB
	dev, err = d.db.GetDeviceByIdentityData(r.IdData)
	if err != nil {
		d.log.Error("failed to find device but could not add either")
		return "", errors.New("failed to locate device")
	}

	areq := &AuthSet{
		IdData:      r.IdData,
		TenantToken: r.TenantToken,
		PubKey:      r.PubKey,
		DeviceId:    dev.Id,
		Status:      DevStatusPending,
	}
	added := true
	// record authentication request
	err = d.db.AddAuthSet(areq)
	if err != nil && err != ErrObjectExists {
		return "", err
	} else if err == ErrObjectExists {
		added = false
	}
	// either the request was added or it was already present in the DB, get
	// it now
	areq, err = d.db.GetAuthSetByDataKey(r.IdData, r.PubKey)
	if err != nil {
		d.log.Error("failed to find device auth set but could not add one either")
		return "", errors.New("failed to locate device auth set")
	}

	// it it was indeed added (a new request), pass it to admission service
	if added || !to.Bool(areq.AdmissionNotified) {
		if err := d.cDevAdm.AddDevice(dev, areq, client); err != nil {
			// we've failed to submit the request, no worries, just
			// return an error
			return "", errors.Wrap(err, "devadm add device error")
		}

		if err := d.db.UpdateAuthSet(areq, &AuthSetUpdate{
			AdmissionNotified: to.BoolPtr(true),
		}); err != nil {
			d.log.Errorf("failed to update auth set data: %v", err)
			// nothing bad happens here, we'll try to post the
			// request next time device pings us
		}

		return "", ErrDevAuthUnauthorized
	}

	// request was already present in DB, check its status
	if areq.Status == DevStatusAccepted {
		// make & give token, include aid when generating token
		token, err := d.jwt.GenerateTokenSignRS256(dev.Id)
		if err != nil {
			return "", errors.Wrap(err, "generate token error")
		}

		if err := d.db.AddToken(token); err != nil {
			return "", errors.Wrap(err, "add token error")
		}

		return token.Token, nil
	}

	// no token, return device unauthorized
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

func (d *DevAuth) AcceptDevice(auth_id string) error {
	if err := d.setAuthSetStatus(auth_id, DevStatusAccepted); err != nil {
		return err
	}

	aset, err := d.db.GetAuthSetById(auth_id)
	if err != nil {
		if err == ErrDevNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	// TODO make this a job for an orchestrator
	if err := d.SubmitInventoryDevice(Device{
		Id: aset.DeviceId,
	}); err != nil {
		return errors.Wrap(err, "inventory device add error")
	}

	return nil
}

func (d *DevAuth) setAuthSetStatus(auth_id string, status string) error {
	aset, err := d.db.GetAuthSetById(auth_id)
	if err != nil {
		if err == ErrDevNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	if status == DevStatusRejected || status == DevStatusPending {
		// delete device token
		err := d.db.DeleteTokenByDevId(aset.DeviceId)
		if err != nil && err != ErrTokenNotFound {
			return errors.Wrap(err, "db delete device token error")
		}
	}

	if err := d.db.UpdateAuthSet(aset, &AuthSetUpdate{
		Status: status,
	}); err != nil {
		return errors.Wrap(err, "db update device auth set error")
	}

	return nil
}

func (d *DevAuth) RejectDevice(auth_id string) error {
	return d.setAuthSetStatus(auth_id, DevStatusRejected)
}

func (d *DevAuth) ResetDevice(auth_id string) error {
	return d.setAuthSetStatus(auth_id, DevStatusPending)
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
