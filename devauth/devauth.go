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
	"net/http"
	"time"

	"github.com/mendersoftware/deviceauth/api"
	"github.com/mendersoftware/deviceauth/client/deviceadm"
	"github.com/mendersoftware/deviceauth/client/inventory"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/pkg/errors"
)

var (
	ErrDevAuthUnauthorized = errors.New("dev auth: unauthorized")
	ErrDevIdAuthIdMismatch = errors.New("dev auth: dev ID and auth ID mismatch")
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
	SubmitAuthRequest(r *model.AuthReq) (string, error)

	GetDevices(skip, limit uint) ([]model.Device, error)
	GetDevice(dev_id string) (*model.Device, error)
	DecommissionDevice(dev_id string) error
	AcceptDeviceAuth(dev_id string, auth_id string) error
	RejectDeviceAuth(dev_id string, auth_id string) error
	ResetDeviceAuth(dev_id string, auth_id string) error
	GetDeviceToken(dev_id string) (*model.Token, error)

	RevokeToken(token_id string) error
	VerifyToken(token string) error
	WithContext(c *api.RequestContext) DevAuthApp

	log.ContextLogger
}

type DevAuth struct {
	db           store.DataStore
	cDevAdm      deviceadm.ClientRunner
	cInv         inventory.InventoryClient
	jwt          jwt.JWTAgentApp
	log          *log.Logger
	clientGetter ApiClientGetter
}

func NewDevAuth(d store.DataStore, cda deviceadm.ClientRunner, ci inventory.InventoryClient, jwt jwt.JWTAgentApp) DevAuthApp {
	return &DevAuth{
		db:           d,
		cDevAdm:      cda,
		cInv:         ci,
		jwt:          jwt,
		log:          log.New(log.Ctx{}),
		clientGetter: simpleApiClientGetter,
	}
}

func (d *DevAuth) getDeviceFromAuthRequest(r *model.AuthReq) (*model.Device, error) {
	dev := model.NewDevice("", r.IdData, r.PubKey, r.TenantToken)

	// record device
	err := d.db.AddDevice(*dev)
	if err != nil && err != store.ErrObjectExists {
		d.log.Errorf("failed to add/find device: %v", err)
		return nil, err
	}

	// either the device was added or it was already present, in any case,
	// pull it from DB
	dev, err = d.db.GetDeviceByIdentityData(r.IdData)
	if err != nil {
		d.log.Error("failed to find device but could not add either")
		return nil, errors.New("failed to locate device")
	}

	// check if the device is in the decommissioning state
	if dev.Decommissioning {
		d.log.Warnf("Device %s in the decommissioning state. %s", dev.Id)
		return nil, ErrDevAuthUnauthorized
	}

	return dev, nil
}

func (d *DevAuth) SubmitAuthRequest(r *model.AuthReq) (string, error) {
	return d.SubmitAuthRequestWithClient(r, d.clientGetter())
}

func (d *DevAuth) SubmitAuthRequestWithClient(r *model.AuthReq, client requestid.ApiRequester) (string, error) {

	// get device associated with given authorization request
	dev, err := d.getDeviceFromAuthRequest(r)
	if err != nil {
		return "", err
	}

	areq := &model.AuthSet{
		IdData:      r.IdData,
		TenantToken: r.TenantToken,
		PubKey:      r.PubKey,
		DeviceId:    dev.Id,
		Status:      model.DevStatusPending,
		Timestamp:   uto.TimePtr(time.Now()),
	}
	added := true
	// record authentication request
	err = d.db.AddAuthSet(*areq)
	if err != nil && err != store.ErrObjectExists {
		return "", err
	} else if err == store.ErrObjectExists {
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
		admreq := deviceadm.AdmReq{
			AuthId:   areq.Id,
			DeviceId: dev.Id,
			IdData:   r.IdData,
			PubKey:   r.PubKey,
		}
		if err := d.cDevAdm.AddDevice(admreq, client); err != nil {
			// we've failed to submit the request, no worries, just
			// return an error
			return "", errors.Wrap(err, "devadm add device error")
		}

		if err := d.db.UpdateAuthSet(*areq, model.AuthSetUpdate{
			AdmissionNotified: to.BoolPtr(true),
		}); err != nil {
			d.log.Errorf("failed to update auth set data: %v", err)
			// nothing bad happens here, we'll try to post the
			// request next time device pings us
		}

		return "", ErrDevAuthUnauthorized
	}

	// request was already present in DB, check its status
	if areq.Status == model.DevStatusAccepted {
		// make & give token, include aid when generating token
		token, err := d.jwt.GenerateTokenSignRS256(dev.Id)
		if err != nil {
			return "", errors.Wrap(err, "generate token error")
		}

		token = token.WithAuthSet(areq)

		if err := d.db.AddToken(*token); err != nil {
			return "", errors.Wrap(err, "add token error")
		}

		return token.Token, nil
	}

	// no token, return device unauthorized
	return "", ErrDevAuthUnauthorized
}

func (d *DevAuth) SubmitInventoryDevice(dev model.Device) error {
	return d.SubmitInventoryDeviceWithClient(dev, d.clientGetter())
}

func (d *DevAuth) SubmitInventoryDeviceWithClient(dev model.Device, client requestid.ApiRequester) error {
	err := d.cInv.AddDevice(&dev, client)
	if err != nil {
		return errors.Wrap(err, "failed to add device to inventory")
	}
	return nil
}

func (d *DevAuth) GetDevices(skip, limit uint) ([]model.Device, error) {
	devs, err := d.db.GetDevices(skip, limit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list devices")
	}

	for i := range devs {
		devs[i].AuthSets, err = d.db.GetAuthSetsForDevice(devs[i].Id)
		if err != nil && err != store.ErrDevNotFound {
			return nil, errors.Wrap(err, "db get auth sets error")
		}
	}
	return devs, err
}

func (d *DevAuth) GetDevice(devId string) (*model.Device, error) {
	dev, err := d.db.GetDeviceById(devId)
	if err != nil {
		if err != store.ErrDevNotFound {
			return nil, errors.Wrap(err, "db get device by id error")
		}
		return nil, err
	}

	dev.AuthSets, err = d.db.GetAuthSetsForDevice(dev.Id)
	if err != nil {
		if err != store.ErrDevNotFound {
			return nil, errors.Wrap(err, "db get auth sets error")
		}
		return nil, err
	}
	return dev, err
}

// DecommissionDevice deletes device and all its tokens
// TODO: submit device decommission job
func (d *DevAuth) DecommissionDevice(devId string) error {
	d.log.Warnf("Decommission device with id: %s", devId)

	// set decommissioning flag on the device
	updev := &model.Device{Id: devId, Decommissioning: true}
	if err := d.db.UpdateDevice(updev); err != nil {
		return err
	}

	// delete device athorization sets
	if err := d.db.DeleteAuthSetsForDevice(devId); err != nil && err != store.ErrAuthSetNotFound {
		return errors.Wrap(err, "db delete device authorization sets error")
	}

	// delete device tokens
	if err := d.db.DeleteTokenByDevId(devId); err != nil && err != store.ErrTokenNotFound {
		return errors.Wrap(err, "db delete device tokens error")
	}

	// delete device
	return d.db.DeleteDevice(devId)
}

func (d *DevAuth) AcceptDeviceAuth(device_id string, auth_id string) error {
	if err := d.setAuthSetStatus(device_id, auth_id, model.DevStatusAccepted); err != nil {
		return err
	}

	aset, err := d.db.GetAuthSetById(auth_id)
	if err != nil {
		if err == store.ErrDevNotFound {
			return err
		}
		return errors.Wrapf(err, "db get auth set error")
	}

	// TODO make this a job for an orchestrator
	if err := d.SubmitInventoryDevice(model.Device{
		Id: aset.DeviceId,
	}); err != nil {
		return errors.Wrap(err, "inventory device add error")
	}

	return nil
}

func (d *DevAuth) setAuthSetStatus(device_id string, auth_id string, status string) error {
	aset, err := d.db.GetAuthSetById(auth_id)
	if err != nil {
		if err == store.ErrDevNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	if aset.DeviceId != device_id {
		return ErrDevIdAuthIdMismatch
	}

	if status == model.DevStatusRejected || status == model.DevStatusPending {
		// delete device token
		err := d.db.DeleteTokenByDevId(aset.DeviceId)
		if err != nil && err != store.ErrTokenNotFound {
			return errors.Wrap(err, "db delete device token error")
		}
	}

	if err := d.db.UpdateAuthSet(*aset, model.AuthSetUpdate{
		Status: status,
	}); err != nil {
		return errors.Wrap(err, "db update device auth set error")
	}

	return nil
}

func (d *DevAuth) RejectDeviceAuth(device_id string, auth_id string) error {
	return d.setAuthSetStatus(device_id, auth_id, model.DevStatusRejected)
}

func (d *DevAuth) ResetDeviceAuth(device_id string, auth_id string) error {
	return d.setAuthSetStatus(device_id, auth_id, model.DevStatusPending)
}

func (*DevAuth) GetDeviceToken(dev_id string) (*model.Token, error) {
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
		if err == jwt.ErrTokenExpired {
			d.log.Errorf("Token %s expired: %v", jti, err)
			err := d.db.DeleteToken(jti)
			if err == store.ErrTokenNotFound {
				d.log.Errorf("Token with jti: %s not found", jti)
				return err
			}
			if err != nil {
				return errors.Wrapf(err, "Cannot delete token with jti: %s : %s", jti, err)
			}
			return jwt.ErrTokenExpired
		}
		d.log.Errorf("Token invalid: %v", err)
		return jwt.ErrTokenInvalid
	}
	// check if token is in the system
	tok, err := d.db.GetToken(jti)
	if err != nil {
		if err == store.ErrTokenNotFound {
			d.log.Errorf("Token with jti: %s not found", jti)
			return err
		}
		return errors.Wrapf(err, "Cannot get token with id: %s from database: %s", jti, err)
	}

	auth, err := d.db.GetAuthSetById(tok.AuthSetId)
	if err != nil {
		if err == store.ErrTokenNotFound {
			d.log.Errorf("auth set %v for token jti: %s not found",
				tok.AuthSetId, jti)
			return err
		}
		return err
	}

	if auth.Status != model.DevStatusAccepted {
		return jwt.ErrTokenInvalid
	}

	return nil
}

func (d *DevAuth) WithContext(ctx *api.RequestContext) DevAuthApp {
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
