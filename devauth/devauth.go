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
	"time"

	"github.com/mendersoftware/deviceauth/client/deviceadm"
	"github.com/mendersoftware/deviceauth/client/inventory"
	"github.com/mendersoftware/deviceauth/client/orchestrator"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"
	"github.com/mendersoftware/go-lib-micro/apiclient"

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
type ApiClientGetter func() apiclient.HttpRunner

func simpleApiClientGetter() apiclient.HttpRunner {
	return &apiclient.HttpApi{}
}

// this device auth service interface
type App interface {
	SubmitAuthRequest(ctx context.Context, r *model.AuthReq) (string, error)

	GetDevices(ctx context.Context, skip, limit uint) ([]model.Device, error)
	GetDevice(ctx context.Context, dev_id string) (*model.Device, error)
	DecommissionDevice(ctx context.Context, dev_id string) error
	AcceptDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	RejectDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	ResetDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	GetDeviceToken(ctx context.Context, dev_id string) (*model.Token, error)

	RevokeToken(ctx context.Context, token_id string) error
	VerifyToken(ctx context.Context, token string) error
}

type DevAuth struct {
	db           store.DataStore
	cDevAdm      deviceadm.ClientRunner
	cInv         inventory.ClientRunner
	cOrch        orchestrator.ClientRunner
	jwt          jwt.JWTAgentApp
	clientGetter ApiClientGetter
}

func NewDevAuth(d store.DataStore, cda deviceadm.ClientRunner, ci inventory.ClientRunner, co orchestrator.ClientRunner, jwt jwt.JWTAgentApp) App {
	return &DevAuth{
		db:           d,
		cDevAdm:      cda,
		cInv:         ci,
		cOrch:        co,
		jwt:          jwt,
		clientGetter: simpleApiClientGetter,
	}
}

func (d *DevAuth) getDeviceFromAuthRequest(ctx context.Context, r *model.AuthReq) (*model.Device, error) {
	dev := model.NewDevice("", r.IdData, r.PubKey, r.TenantToken)

	l := log.FromContext(ctx)

	// record device
	err := d.db.AddDevice(ctx, *dev)
	if err != nil && err != store.ErrObjectExists {
		l.Errorf("failed to add/find device: %v", err)
		return nil, err
	}

	// either the device was added or it was already present, in any case,
	// pull it from DB
	dev, err = d.db.GetDeviceByIdentityData(ctx, r.IdData)
	if err != nil {
		l.Error("failed to find device but could not add either")
		return nil, errors.New("failed to locate device")
	}

	// check if the device is in the decommissioning state
	if dev.Decommissioning {
		l.Warnf("Device %s in the decommissioning state. %s", dev.Id)
		return nil, ErrDevAuthUnauthorized
	}

	return dev, nil
}

func (d *DevAuth) SubmitAuthRequest(ctx context.Context, r *model.AuthReq) (string, error) {
	return d.SubmitAuthRequestWithClient(ctx, r, d.clientGetter())
}

func (d *DevAuth) SubmitAuthRequestWithClient(ctx context.Context, r *model.AuthReq, client requestid.ApiRequester) (string, error) {

	l := log.FromContext(ctx)

	// get device associated with given authorization request
	dev, err := d.getDeviceFromAuthRequest(ctx, r)
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
	err = d.db.AddAuthSet(ctx, *areq)
	if err != nil && err != store.ErrObjectExists {
		return "", err
	} else if err == store.ErrObjectExists {
		added = false
	}
	// either the request was added or it was already present in the DB, get
	// it now
	areq, err = d.db.GetAuthSetByDataKey(ctx, r.IdData, r.PubKey)
	if err != nil {
		l.Error("failed to find device auth set but could not add one either")
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
		if err := d.cDevAdm.AddDevice(ctx, admreq, client); err != nil {
			// we've failed to submit the request, no worries, just
			// return an error
			return "", errors.Wrap(err, "devadm add device error")
		}

		if err := d.db.UpdateAuthSet(ctx, *areq, model.AuthSetUpdate{
			AdmissionNotified: to.BoolPtr(true),
		}); err != nil {
			l.Errorf("failed to update auth set data: %v", err)
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

		if err := d.db.AddToken(ctx, *token); err != nil {
			return "", errors.Wrap(err, "add token error")
		}

		l.Infof("Token %v assigned to device %v auth set %v",
			token.Id, dev.Id, areq.Id)
		return token.Token, nil
	}

	// no token, return device unauthorized
	return "", ErrDevAuthUnauthorized
}

func (d *DevAuth) SubmitInventoryDevice(ctx context.Context, dev model.Device) error {
	return d.SubmitInventoryDeviceWithClient(ctx, dev, d.clientGetter())
}

func (d *DevAuth) SubmitInventoryDeviceWithClient(ctx context.Context, dev model.Device, client requestid.ApiRequester) error {
	err := d.cInv.AddDevice(ctx, inventory.AddReq{Id: dev.Id}, client)
	if err != nil {
		return errors.Wrap(err, "failed to add device to inventory")
	}
	return nil
}

func (d *DevAuth) GetDevices(ctx context.Context, skip, limit uint) ([]model.Device, error) {
	devs, err := d.db.GetDevices(ctx, skip, limit)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list devices")
	}

	for i := range devs {
		devs[i].AuthSets, err = d.db.GetAuthSetsForDevice(ctx, devs[i].Id)
		if err != nil && err != store.ErrDevNotFound {
			return nil, errors.Wrap(err, "db get auth sets error")
		}
	}
	return devs, err
}

func (d *DevAuth) GetDevice(ctx context.Context, devId string) (*model.Device, error) {
	dev, err := d.db.GetDeviceById(ctx, devId)
	if err != nil {
		if err != store.ErrDevNotFound {
			return nil, errors.Wrap(err, "db get device by id error")
		}
		return nil, err
	}

	dev.AuthSets, err = d.db.GetAuthSetsForDevice(ctx, dev.Id)
	if err != nil {
		if err != store.ErrDevNotFound {
			return nil, errors.Wrap(err, "db get auth sets error")
		}
		return nil, err
	}
	return dev, err
}

// DecommissionDevice deletes device and all its tokens
func (d *DevAuth) DecommissionDevice(ctx context.Context, devId string) error {

	l := log.FromContext(ctx)

	l.Warnf("Decommission device with id: %s", devId)

	// set decommissioning flag on the device
	updev := model.DeviceUpdate{
		Decommissioning: to.BoolPtr(true),
	}
	if err := d.db.UpdateDevice(ctx, model.Device{Id: devId}, updev); err != nil {
		return err
	}

	reqId := requestid.FromContext(ctx)

	// submit device decommissioning job
	if err := d.cOrch.SubmitDeviceDecommisioningJob(
		ctx,
		orchestrator.DecommissioningReq{
			DeviceId:  devId,
			RequestId: reqId,
		}); err != nil {
		return errors.Wrap(err, "submit device decommissioning job error")
	}

	// delete device athorization sets
	if err := d.db.DeleteAuthSetsForDevice(ctx, devId); err != nil && err != store.ErrAuthSetNotFound {
		return errors.Wrap(err, "db delete device authorization sets error")
	}

	// delete device tokens
	if err := d.db.DeleteTokenByDevId(ctx, devId); err != nil && err != store.ErrTokenNotFound {
		return errors.Wrap(err, "db delete device tokens error")
	}

	// delete device
	return d.db.DeleteDevice(ctx, devId)
}

func (d *DevAuth) AcceptDeviceAuth(ctx context.Context, device_id string, auth_id string) error {
	if err := d.setAuthSetStatus(ctx, device_id, auth_id, model.DevStatusAccepted); err != nil {
		return err
	}

	aset, err := d.db.GetAuthSetById(ctx, auth_id)
	if err != nil {
		if err == store.ErrDevNotFound {
			return err
		}
		return errors.Wrapf(err, "db get auth set error")
	}

	// TODO make this a job for an orchestrator
	if err := d.SubmitInventoryDevice(ctx, model.Device{
		Id: aset.DeviceId,
	}); err != nil {
		return errors.Wrap(err, "inventory device add error")
	}

	return nil
}

func (d *DevAuth) setAuthSetStatus(ctx context.Context, device_id string, auth_id string, status string) error {
	aset, err := d.db.GetAuthSetById(ctx, auth_id)
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
		err := d.db.DeleteTokenByDevId(ctx, aset.DeviceId)
		if err != nil && err != store.ErrTokenNotFound {
			return errors.Wrap(err, "db delete device token error")
		}
	}

	if err := d.db.UpdateAuthSet(ctx, *aset, model.AuthSetUpdate{
		Status: status,
	}); err != nil {
		return errors.Wrap(err, "db update device auth set error")
	}

	return nil
}

func (d *DevAuth) RejectDeviceAuth(ctx context.Context, device_id string, auth_id string) error {
	return d.setAuthSetStatus(ctx, device_id, auth_id, model.DevStatusRejected)
}

func (d *DevAuth) ResetDeviceAuth(ctx context.Context, device_id string, auth_id string) error {
	return d.setAuthSetStatus(ctx, device_id, auth_id, model.DevStatusPending)
}

func (*DevAuth) GetDeviceToken(ctx context.Context, dev_id string) (*model.Token, error) {
	return nil, errors.New("not implemented")
}

func (d *DevAuth) RevokeToken(ctx context.Context, token_id string) error {

	l := log.FromContext(ctx)

	l.Warnf("Revoke token with jti: %s", token_id)

	return d.db.DeleteToken(ctx, token_id)
}

func (d *DevAuth) VerifyToken(ctx context.Context, token string) error {

	l := log.FromContext(ctx)

	// validate signature and claims
	jti, err := d.jwt.ValidateTokenSignRS256(token)
	if err != nil {
		if err == jwt.ErrTokenExpired {
			l.Errorf("Token %s expired: %v", jti, err)
			err := d.db.DeleteToken(ctx, jti)
			if err == store.ErrTokenNotFound {
				l.Errorf("Token %s not found", jti)
				return err
			}
			if err != nil {
				return errors.Wrapf(err, "Cannot delete token with jti: %s : %s", jti, err)
			}
			return jwt.ErrTokenExpired
		}
		l.Errorf("Token %s invalid: %v", jti, err)
		return jwt.ErrTokenInvalid
	}
	// check if token is in the system
	tok, err := d.db.GetToken(ctx, jti)
	if err != nil {
		if err == store.ErrTokenNotFound {
			l.Errorf("Token %s not found", jti)
			return err
		}
		return errors.Wrapf(err, "Cannot get token with id: %s from database: %s", jti, err)
	}

	auth, err := d.db.GetAuthSetById(ctx, tok.AuthSetId)
	if err != nil {
		if err == store.ErrTokenNotFound {
			l.Errorf("Token %s auth set %s not found",
				jti, tok.AuthSetId)
			return err
		}
		return err
	}

	if auth.Status != model.DevStatusAccepted {
		return jwt.ErrTokenInvalid
	}

	// reject authentication for device that is in the process of
	// decommissioning
	dev, err := d.db.GetDeviceById(ctx, auth.DeviceId)
	if err != nil {
		return err
	}
	if dev.Decommissioning {
		l.Errorf("Token %s rejected, device %s is being decommissioned", jti, auth.DeviceId)
		return jwt.ErrTokenInvalid
	}

	return nil
}
