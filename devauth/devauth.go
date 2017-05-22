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

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"

	"github.com/mendersoftware/deviceauth/client/deviceadm"
	"github.com/mendersoftware/deviceauth/client/inventory"
	"github.com/mendersoftware/deviceauth/client/orchestrator"
	"github.com/mendersoftware/deviceauth/client/tenant"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	uto "github.com/mendersoftware/deviceauth/utils/to"
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
	cTenant      tenant.ClientRunner
	jwt          jwt.Handler
	clientGetter ApiClientGetter
	verifyTenant bool
	config       Config
}

type Config struct {
	// token issuer
	Issuer string
	// token expiration time
	ExpirationTime int64
}

func NewDevAuth(d store.DataStore, cda deviceadm.ClientRunner,
	ci inventory.ClientRunner, co orchestrator.ClientRunner,
	jwt jwt.Handler, config Config) *DevAuth {

	return &DevAuth{
		db:           d,
		cDevAdm:      cda,
		cInv:         ci,
		cOrch:        co,
		jwt:          jwt,
		clientGetter: simpleApiClientGetter,
		verifyTenant: false,
		config:       config,
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

func (d *DevAuth) signToken(ctx context.Context) jwt.SignFunc {
	return func(t *jwt.Token) (string, error) {
		return d.jwt.ToJWT(t)
	}
}

func (d *DevAuth) SubmitAuthRequest(ctx context.Context, r *model.AuthReq) (string, error) {
	l := log.FromContext(ctx)

	if d.verifyTenant {
		if r.TenantToken == "" {
			l.Errorf("request is missing tenant token")
			return "", ErrDevAuthUnauthorized
		}

		// verify tenant token with tenant administration
		err := d.cTenant.VerifyToken(ctx, r.TenantToken, d.clientGetter())
		if err != nil {
			if err == tenant.ErrTokenVerificationFailed {
				l.Errorf("failed to verify tenant token")
				return "", ErrDevAuthUnauthorized
			}

			return "", errors.New("request to verify tenant token failed")
		}

		ident, err := identity.ExtractIdentity(r.TenantToken)
		l.Infof("identity %v", ident)
		if err != nil {
			l.Errorf("failed to extract identity: %v", err)
			return "", ErrDevAuthUnauthorized
		}

		// update context to store the identity of the caller
		ctx = identity.WithContext(ctx, &ident)
	}

	authSet, err := d.processAuthRequest(ctx, r)
	if err != nil {
		return "", err
	}

	// request was already present in DB, check its status
	if authSet.Status == model.DevStatusAccepted {
		rawJwt := &jwt.Token{
			Claims: jwt.Claims{
				ID:        uuid.NewV4().String(),
				Issuer:    d.config.Issuer,
				ExpiresAt: time.Now().Unix() + d.config.ExpirationTime,
				Subject:   authSet.DeviceId,
			},
		}

		// sign and encode as JWT
		raw, err := rawJwt.MarshalJWT(d.signToken(ctx))
		if err != nil {
			return "", errors.Wrap(err, "generate token error")
		}

		token := model.NewToken(rawJwt.Claims.ID, authSet.DeviceId, string(raw))
		token = token.WithAuthSet(authSet)

		if err := d.db.AddToken(ctx, *token); err != nil {
			return "", errors.Wrap(err, "add token error")
		}

		l.Infof("Token %v assigned to device %v auth set %v",
			token.Id, authSet.DeviceId, authSet.Id)
		return token.Token, nil
	}

	// no token, return device unauthorized
	return "", ErrDevAuthUnauthorized

}

// processAuthRequest will process incoming auth request, record authentication
// data information it contains and optionally upload the data to device
// admission service. Returns a tupe (auth set, error). If no errors were
// present, model.AuthSet.Status will indicate the status of device admission
func (d *DevAuth) processAuthRequest(ctx context.Context, r *model.AuthReq) (*model.AuthSet, error) {

	l := log.FromContext(ctx)

	// get device associated with given authorization request
	dev, err := d.getDeviceFromAuthRequest(ctx, r)
	if err != nil {
		return nil, err
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
		return nil, err
	} else if err == store.ErrObjectExists {
		added = false
	}
	// either the request was added or it was already present in the DB, get
	// it now
	areq, err = d.db.GetAuthSetByDataKey(ctx, r.IdData, r.PubKey)
	if err != nil {
		l.Error("failed to find device auth set but could not add one either")
		return nil, errors.New("failed to locate device auth set")
	}

	// it it was indeed added (a new request), pass it to admission service
	if added || !to.Bool(areq.AdmissionNotified) {
		admreq := deviceadm.AdmReq{
			AuthId:   areq.Id,
			DeviceId: dev.Id,
			IdData:   r.IdData,
			PubKey:   r.PubKey,
		}
		if err := d.cDevAdm.AddDevice(ctx, admreq, d.clientGetter()); err != nil {
			// we've failed to submit the request, no worries, just
			// return an error
			return nil, errors.Wrap(err, "devadm add device error")
		}

		if err := d.db.UpdateAuthSet(ctx, *areq, model.AuthSetUpdate{
			AdmissionNotified: to.BoolPtr(true),
		}); err != nil {
			l.Errorf("failed to update auth set data: %v", err)
			// nothing bad happens here, we'll try to post the
			// request next time device pings us
		}
	}

	return areq, nil
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

func (d *DevAuth) VerifyToken(ctx context.Context, raw string) error {

	l := log.FromContext(ctx)

	token := &jwt.Token{}

	err := token.UnmarshalJWT([]byte(raw), d.jwt.FromJWT)
	jti := token.Claims.ID
	if err != nil {
		if err == jwt.ErrTokenExpired && jti != "" {
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

// WithTenantVerification will force verification of tenant token with tenant
// administrator when processing device authentication requests. Returns an
// updated devauth.
func (d *DevAuth) WithTenantVerification(c tenant.ClientRunner) *DevAuth {
	d.cTenant = c
	d.verifyTenant = true
	return d
}
