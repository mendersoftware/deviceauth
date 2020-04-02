// Copyright 2019 Northern.tech AS
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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/apiclient"
	ctxhttpheader "github.com/mendersoftware/go-lib-micro/context/httpheader"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/mendersoftware/deviceauth/client/orchestrator"
	"github.com/mendersoftware/deviceauth/client/tenant"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	"github.com/mendersoftware/deviceauth/store/mongo"
	uto "github.com/mendersoftware/deviceauth/utils/to"
)

const (
	MsgErrDevAuthUnauthorized = "dev auth: unauthorized"
	MsgErrDevAuthBadRequest   = "dev auth: bad request"
)

var (
	ErrDevAuthUnauthorized   = errors.New(MsgErrDevAuthUnauthorized)
	ErrDevIdAuthIdMismatch   = errors.New("dev auth: dev ID and auth ID mismatch")
	ErrMaxDeviceCountReached = errors.New("maximum number of accepted devices reached")
	ErrDeviceExists          = errors.New("device already exists")
	ErrDeviceNotFound        = errors.New("device not found")
	ErrDevAuthBadRequest     = errors.New(MsgErrDevAuthBadRequest)
)

func IsErrDevAuthUnauthorized(e error) bool {
	return strings.HasPrefix(e.Error(), MsgErrDevAuthUnauthorized)
}

func MakeErrDevAuthUnauthorized(e error) error {
	return errors.Wrap(e, MsgErrDevAuthUnauthorized)
}

func IsErrDevAuthBadRequest(e error) bool {
	return strings.HasPrefix(e.Error(), MsgErrDevAuthBadRequest)
}

func MakeErrDevAuthBadRequest(e error) error {
	return errors.Wrap(e, MsgErrDevAuthBadRequest)
}

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

	GetDevices(ctx context.Context, skip, limit uint, filter store.DeviceFilter) ([]model.Device, error)
	GetDevice(ctx context.Context, dev_id string) (*model.Device, error)
	DecommissionDevice(ctx context.Context, dev_id string) error
	DeleteAuthSet(ctx context.Context, dev_id string, auth_id string) error
	AcceptDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	RejectDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	ResetDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	PreauthorizeDevice(ctx context.Context, req *model.PreAuthReq) error
	GetDeviceToken(ctx context.Context, dev_id string) (*model.Token, error)

	RevokeToken(ctx context.Context, token_id string) error
	VerifyToken(ctx context.Context, token string) error
	DeleteTokens(ctx context.Context, tenant_id, device_id string) error

	SetTenantLimit(ctx context.Context, tenant_id string, limit model.Limit) error

	GetLimit(ctx context.Context, name string) (*model.Limit, error)
	GetTenantLimit(ctx context.Context, name, tenant_id string) (*model.Limit, error)

	GetDevCountByStatus(ctx context.Context, status string) (int, error)

	ProvisionTenant(ctx context.Context, tenant_id string) error

	GetTenantDeviceStatus(ctx context.Context, tenantId, deviceId string) (*model.Status, error)
}

type DevAuth struct {
	db           store.DataStore
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
	// max devices limit default
	MaxDevicesLimitDefault uint64
	// Default tenant token to use when the client supplies none. Can be
	// empty
	DefaultTenantToken string
}

func NewDevAuth(d store.DataStore, co orchestrator.ClientRunner,
	jwt jwt.Handler, config Config) *DevAuth {

	return &DevAuth{
		db:           d,
		cOrch:        co,
		jwt:          jwt,
		clientGetter: simpleApiClientGetter,
		verifyTenant: false,
		config:       config,
	}
}

func (d *DevAuth) getDeviceFromAuthRequest(ctx context.Context, r *model.AuthReq) (*model.Device, error) {
	dev := model.NewDevice("", r.IdData, r.PubKey)

	l := log.FromContext(ctx)

	idDataStruct, idDataSha256, err := parseIdData(r.IdData)
	if err != nil {
		return nil, MakeErrDevAuthBadRequest(err)
	}

	dev.IdDataStruct = idDataStruct
	dev.IdDataSha256 = idDataSha256

	// record device
	err = d.db.AddDevice(ctx, *dev)
	if err != nil && err != store.ErrObjectExists {
		l.Errorf("failed to add/find device: %v", err)
		return nil, err
	}

	// either the device was added or it was already present, in any case,
	// pull it from DB
	dev, err = d.db.GetDeviceByIdentityDataHash(ctx, idDataSha256)
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

// tenantWithContext will update `ctx` with tenant related data
func tenantWithContext(ctx context.Context, tenantToken string) (context.Context, error) {
	ident, err := identity.ExtractIdentity(tenantToken)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract identity from tenant token")
	}

	// update context to store the identity of the caller
	ctx = identity.WithContext(ctx, &ident)

	// setup authorization header so that outgoing requests are done for
	// *this* tenant
	ctx = ctxhttpheader.WithContext(ctx,
		http.Header{
			"Authorization": []string{fmt.Sprintf("Bearer %s", tenantToken)},
		},
		"Authorization")

	return ctx, nil
}

// This function explicitly returns string pointer, not string, so that in the
// event that we have made a logic error somewhere, we will get a nil-pointer
// exception instead of a incorrect succeeded login, which would be very bad for
// security.
func logAndGetCorrectTenantToken(l *log.Logger, tenantToken, defaultTenantToken string,
	errToken, errDefaultToken error) (*string, error) {
	// The logic here is: If any error is nil, we return success immediately
	// (authentication succeeded). If both are non-nil, we consider "missing
	// token" errors priority 2, and all other errors priority 1. Then we
	// log all errors at the most serious level. So "missing token" errors
	// will not be logged if there is another more serious error present.

	if errToken == nil {
		return &tenantToken, nil
	}
	if errDefaultToken == nil {
		return &defaultTenantToken, nil
	}

	var returnError error

	if errToken != nil && !tenant.IsErrTokenMissing(errToken) {
		l.Errorf("Failed to verify supplied tenant token: %s", errToken.Error())
		returnError = errToken
	}
	if errDefaultToken != nil && !tenant.IsErrTokenMissing(errDefaultToken) {
		l.Errorf("Failed to verify default tenant token: %s", errDefaultToken.Error())
		if returnError == nil {
			returnError = errDefaultToken
		}
	}

	if returnError == nil {
		if errToken != nil {
			l.Errorf("Failed to verify supplied tenant token: %s", errToken.Error())
			returnError = errToken
		}
		if errDefaultToken != nil {
			l.Errorf("Failed to verify default tenant token: %s", errDefaultToken.Error())
			returnError = errDefaultToken
		}
	}

	if tenant.IsErrTokenVerificationFailed(returnError) || tenant.IsErrTokenMissing(returnError) {
		return nil, MakeErrDevAuthUnauthorized(returnError)
	} else {
		return nil, errors.Wrap(returnError, "request to verify tenant token failed")
	}
}

func (d *DevAuth) verifyTenantToken(ctx context.Context, tenantToken, defaultTenantToken string) (context.Context, error) {
	l := log.FromContext(ctx)

	errToken := errors.New(tenant.MsgErrTokenMissing)
	errDefaultToken := errToken

	// verify tenant token with tenant administration, and fall back to
	// verifying default tenant token if that fails.
	if tenantToken != "" {
		errToken = d.cTenant.VerifyToken(ctx, tenantToken, d.clientGetter())
	}
	if errToken != nil && defaultTenantToken != "" {
		errDefaultToken = d.cTenant.VerifyToken(ctx, defaultTenantToken, d.clientGetter())
	}

	chosenTenantToken, err := logAndGetCorrectTenantToken(l, tenantToken, defaultTenantToken, errToken, errDefaultToken)
	if err != nil {
		return ctx, err
	}

	tCtx, err := tenantWithContext(ctx, *chosenTenantToken)
	if err != nil {
		l.Errorf("failed to setup tenant context: %v", err)
		return ctx, ErrDevAuthUnauthorized
	}

	// return updated context
	return tCtx, nil
}

func (d *DevAuth) SubmitAuthRequest(ctx context.Context, r *model.AuthReq) (string, error) {
	l := log.FromContext(ctx)

	if d.verifyTenant {
		tctx, err := d.verifyTenantToken(ctx, r.TenantToken, d.config.DefaultTenantToken)
		if err != nil {
			return "", err
		}

		// update context
		ctx = tctx
	}

	// first, try to handle preauthorization
	authSet, err := d.processPreAuthRequest(ctx, r)
	if err != nil {
		return "", err
	}

	// if not a preauth request, process with regular auth request handling
	if authSet == nil {
		authSet, err = d.processAuthRequest(ctx, r)
		if err != nil {
			return "", err
		}
	}

	uid, err := uuid.NewV4()
	if err != nil {
		l.Errorf("failed to assign uuid: %v", err)
		return "", err
	}

	// request was already present in DB, check its status
	if authSet.Status == model.DevStatusAccepted {
		rawJwt := &jwt.Token{
			Claims: jwt.Claims{
				ID:        uid.String(),
				Issuer:    d.config.Issuer,
				ExpiresAt: time.Now().Unix() + d.config.ExpirationTime,
				Subject:   authSet.DeviceId,
				Device:    true,
			},
		}

		if d.verifyTenant {
			// update token tenant claim if needed
			ident := identity.FromContext(ctx)
			if ident != nil && ident.Tenant != "" {
				rawJwt.Claims.Tenant = ident.Tenant
			}
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

func (d *DevAuth) processPreAuthRequest(ctx context.Context, r *model.AuthReq) (*model.AuthSet, error) {
	var deviceAlreadyAccepted bool

	_, idDataSha256, err := parseIdData(r.IdData)
	if err != nil {
		return nil, MakeErrDevAuthBadRequest(err)
	}

	// authset exists?
	aset, err := d.db.GetAuthSetByIdDataHashKey(ctx, idDataSha256, r.PubKey)
	switch err {
	case nil:
		break
	case store.ErrAuthSetNotFound:
		return nil, nil
	default:
		return nil, errors.Wrap(err, "failed to fetch auth set")
	}

	// if authset status is not 'preauthorized', nothing to do
	if aset.Status != model.DevStatusPreauth {
		return nil, nil
	}

	// check the device status
	// if the device status is accepted then do not trigger provisioning workflow
	// this needs to be checked before changing authentication set status
	dev, err := d.db.GetDeviceById(ctx, aset.DeviceId)
	if err != nil {
		return nil, err
	}

	if dev.Status == model.DevStatusAccepted {
		deviceAlreadyAccepted = true
	}

	// auth set is ok for auto-accepting, check device limit
	allow, err := d.canAcceptDevice(ctx)
	if err != nil {
		return nil, err
	}

	if !allow {
		return nil, ErrMaxDeviceCountReached
	}

	if !deviceAlreadyAccepted {
		reqId := requestid.FromContext(ctx)

		// submit device accepted job
		if err := d.cOrch.SubmitProvisionDeviceJob(
			ctx,
			orchestrator.ProvisionDeviceReq{
				RequestId:     reqId,
				Authorization: ctxhttpheader.FromContext(ctx, "Authorization"),
				Device: model.Device{
					Id: aset.DeviceId,
				},
			}); err != nil {
			return nil, errors.Wrap(err, "submit device provisioning job error")
		}
	}

	// persist the 'accepted' status in both auth set, and device
	if err := d.db.UpdateAuthSetById(ctx, aset.Id, model.AuthSetUpdate{
		Status: model.DevStatusAccepted,
	}); err != nil {
		return nil, errors.Wrap(err, "failed to update auth set status")
	}

	if err := d.updateDeviceStatus(ctx, aset.DeviceId, model.DevStatusAccepted); err != nil {
		return nil, err
	}

	aset.Status = model.DevStatusAccepted
	return aset, nil
}

func (d *DevAuth) updateDeviceStatus(ctx context.Context, devId, status string) error {
	if status == "" {
		newStatus, err := d.db.GetDeviceStatus(ctx, devId)
		switch err {
		case nil:
			status = newStatus
		case store.ErrAuthSetNotFound:
			status = model.DevStatusRejected
		default:
			return errors.Wrap(err, "Cannot determine device status")
		}
	}

	if err := d.db.UpdateDevice(ctx,
		model.Device{
			Id: devId,
		},
		model.DeviceUpdate{
			Status:    status,
			UpdatedTs: uto.TimePtr(time.Now().UTC()),
		}); err != nil {
		return errors.Wrap(err, "failed to update device status")
	}
	return nil
}

// processAuthRequest will process incoming auth request and record authentication
// data information it contains. Returns a tupe (auth set, error). If no errors were
// present, model.AuthSet.Status will indicate the status of device admission
func (d *DevAuth) processAuthRequest(ctx context.Context, r *model.AuthReq) (*model.AuthSet, error) {

	l := log.FromContext(ctx)

	// get device associated with given authorization request
	dev, err := d.getDeviceFromAuthRequest(ctx, r)
	if err != nil {
		return nil, err
	}

	idDataStruct, idDataSha256, err := parseIdData(r.IdData)
	if err != nil {
		return nil, MakeErrDevAuthBadRequest(err)
	}

	areq := &model.AuthSet{
		IdData:       r.IdData,
		IdDataStruct: idDataStruct,
		IdDataSha256: idDataSha256,
		PubKey:       r.PubKey,
		DeviceId:     dev.Id,
		Group:        dev.Group,
		Status:       model.DevStatusPending,
		Timestamp:    uto.TimePtr(time.Now()),
	}

	// record authentication request
	err = d.db.AddAuthSet(ctx, *areq)
	if err != nil && err != store.ErrObjectExists {
		return nil, err
	}

	// update the device status
	if err := d.updateDeviceStatus(ctx, dev.Id, ""); err != nil {
		return nil, err
	}

	// either the request was added or it was already present in the DB, get
	// it now
	areq, err = d.db.GetAuthSetByIdDataHashKey(ctx, idDataSha256, r.PubKey)
	if err != nil {
		l.Error("failed to find device auth set but could not add one either")
		return nil, errors.New("failed to locate device auth set")
	}

	return areq, nil
}

func (d *DevAuth) GetDevices(ctx context.Context, skip, limit uint, filter store.DeviceFilter) ([]model.Device, error) {
	devs, err := d.db.GetDevices(ctx, skip, limit, filter)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list devices")
	}

	for i := range devs {
		devs[i].AuthSets, err = d.db.GetAuthSetsForDevice(ctx, devs[i].Id)
		if err != nil && err != store.ErrAuthSetNotFound {
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
		if err != store.ErrAuthSetNotFound {
			return nil, errors.Wrap(err, "db get auth sets error")
		}
		return dev, nil
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
			DeviceId:      devId,
			RequestId:     reqId,
			Authorization: ctxhttpheader.FromContext(ctx, "Authorization"),
		}); err != nil {
		return errors.Wrap(err, "submit device decommissioning job error")
	}

	// delete device authorization sets
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

// Deletes device authentication set, and optionally the device.
func (d *DevAuth) DeleteAuthSet(ctx context.Context, devId string, authId string) error {

	l := log.FromContext(ctx)

	l.Warnf("Delete authentication set with id: %s for the device with id: %s", authId, devId)

	// retrieve device authentication set to check its status
	authSet, err := d.db.GetAuthSetById(ctx, authId)
	if err != nil {
		if err == store.ErrAuthSetNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	// if the device authentication set is accepted delete device tokens
	if authSet.Status == model.DevStatusAccepted {
		if err := d.db.DeleteTokenByDevId(ctx, devId); err != nil && err != store.ErrTokenNotFound {
			return errors.Wrap(err, "db delete device tokens error")
		}
	}

	// delete device authorization set
	if err := d.db.DeleteAuthSetForDevice(ctx, devId, authId); err != nil {
		return err
	}

	// only delete the device if the set is 'preauthorized'
	// otherwise device data may live in other services too, and is a case for decommissioning
	if authSet.Status == model.DevStatusPreauth {
		return d.db.DeleteDevice(ctx, devId)
	}

	return d.updateDeviceStatus(ctx, devId, "")
}

func (d *DevAuth) AcceptDeviceAuth(ctx context.Context, device_id string, auth_id string) error {
	var deviceAlreadyAccepted bool

	l := log.FromContext(ctx)

	aset, err := d.db.GetAuthSetById(ctx, auth_id)
	if err != nil {
		if err == store.ErrAuthSetNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	// check the device status
	// if the device status is accepted then do not trigger provisioning workflow
	// this needs to be checked before changing authentication set status
	dev, err := d.db.GetDeviceById(ctx, device_id)
	if err != nil {
		return err
	}

	if dev.Status == model.DevStatusAccepted {
		deviceAlreadyAccepted = true
	}

	// device authentication set already accepted, nothing to do here
	if aset.Status == model.DevStatusAccepted {
		l.Debugf("Device %s already accepted", device_id)
		return nil
	}

	// possible race, consider accept-count-unaccept pattern if that's problematic
	allow, err := d.canAcceptDevice(ctx)
	if err != nil {
		return err
	}

	if !allow {
		return ErrMaxDeviceCountReached
	}

	if err := d.setAuthSetStatus(ctx, device_id, auth_id, model.DevStatusAccepted); err != nil {
		return err
	}

	if deviceAlreadyAccepted {
		return nil
	}

	reqId := requestid.FromContext(ctx)

	// submit device accepted job
	if err := d.cOrch.SubmitProvisionDeviceJob(
		ctx,
		orchestrator.ProvisionDeviceReq{
			RequestId:     reqId,
			Authorization: ctxhttpheader.FromContext(ctx, "Authorization"),
			Device: model.Device{
				Id: aset.DeviceId,
			},
		}); err != nil {
		return errors.Wrap(err, "submit device provisioning job error")
	}

	return nil
}

func (d *DevAuth) setAuthSetStatus(ctx context.Context, device_id string, auth_id string, status string) error {
	aset, err := d.db.GetAuthSetById(ctx, auth_id)
	if err != nil {
		if err == store.ErrAuthSetNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	if aset.DeviceId != device_id {
		return ErrDevIdAuthIdMismatch
	}

	if aset.Status == status {
		return nil
	}

	if aset.Status == model.DevStatusAccepted && (status == model.DevStatusRejected || status == model.DevStatusPending) {
		// delete device token
		err := d.db.DeleteTokenByDevId(ctx, aset.DeviceId)
		if err != nil && err != store.ErrTokenNotFound {
			return errors.Wrap(err, "db delete device token error")
		}
	}

	// if accepting an auth set
	if status == model.DevStatusAccepted {
		// reject all accepted auth sets for this device first
		if err := d.db.UpdateAuthSet(ctx,
			bson.M{
				model.AuthSetKeyDeviceId: device_id,
				"$or": []bson.M{
					bson.M{model.AuthSetKeyStatus: model.DevStatusAccepted},
					bson.M{model.AuthSetKeyStatus: model.DevStatusPreauth},
				},
			},
			model.AuthSetUpdate{
				Status: model.DevStatusRejected,
			}); err != nil && err != store.ErrAuthSetNotFound {
			return errors.Wrap(err, "failed to reject auth sets")
		}
	}

	if err := d.db.UpdateAuthSetById(ctx, aset.Id, model.AuthSetUpdate{
		Status: status,
	}); err != nil {
		return errors.Wrap(err, "db update device auth set error")
	}

	if status == model.DevStatusAccepted {
		return d.updateDeviceStatus(ctx, device_id, status)
	} else {
		return d.updateDeviceStatus(ctx, device_id, "")
	}
}

func (d *DevAuth) RejectDeviceAuth(ctx context.Context, device_id string, auth_id string) error {
	return d.setAuthSetStatus(ctx, device_id, auth_id, model.DevStatusRejected)
}

func (d *DevAuth) ResetDeviceAuth(ctx context.Context, device_id string, auth_id string) error {
	return d.setAuthSetStatus(ctx, device_id, auth_id, model.DevStatusPending)
}

func parseIdData(idData string) (map[string]interface{}, []byte, error) {
	var idDataStruct map[string]interface{}
	var idDataSha256 []byte

	err := json.Unmarshal([]byte(idData), &idDataStruct)
	if err != nil {
		return idDataStruct, idDataSha256, errors.Wrapf(err, "failed to parse identity data: %s", idData)
	}

	hash := sha256.New()
	hash.Write([]byte(idData))
	idDataSha256 = hash.Sum(nil)

	return idDataStruct, idDataSha256, nil
}

func (d *DevAuth) PreauthorizeDevice(ctx context.Context, req *model.PreAuthReq) error {
	// try add device, if a device with the given id_data exists -
	// the unique index on id_data will prevent it (conflict)
	// this is the only safeguard against id data conflict - we won't try to handle it
	// additionally on inserting the auth set (can't add an id data index on auth set - would prevent key rotation)

	// FIXME: tenant_token is "" on purpose, will be removed
	dev := model.NewDevice(req.DeviceId, req.IdData, req.PubKey)
	dev.Status = model.DevStatusPreauth

	idDataStruct, idDataSha256, err := parseIdData(req.IdData)
	if err != nil {
		return MakeErrDevAuthBadRequest(err)
	}

	dev.IdDataStruct = idDataStruct
	dev.IdDataSha256 = idDataSha256

	err = d.db.AddDevice(ctx, *dev)
	switch err {
	case nil:
		break
	case store.ErrObjectExists:
		return ErrDeviceExists
	default:
		return errors.Wrap(err, "failed to add device")
	}

	// record authentication request
	authset := model.AuthSet{
		Id:           req.AuthSetId,
		IdData:       req.IdData,
		IdDataStruct: idDataStruct,
		IdDataSha256: idDataSha256,
		PubKey:       req.PubKey,
		DeviceId:     req.DeviceId,
		Status:       model.DevStatusPreauth,
		Timestamp:    uto.TimePtr(time.Now()),
	}

	err = d.db.AddAuthSet(ctx, authset)
	switch err {
	case nil:
		return nil
	case store.ErrObjectExists:
		return ErrDeviceExists
	default:
		return errors.Wrap(err, "failed to add auth set")
	}
}

func (*DevAuth) GetDeviceToken(ctx context.Context, dev_id string) (*model.Token, error) {
	return nil, errors.New("not implemented")
}

func (d *DevAuth) RevokeToken(ctx context.Context, token_id string) error {

	l := log.FromContext(ctx)

	l.Warnf("Revoke token with jti: %s", token_id)

	return d.db.DeleteToken(ctx, token_id)
}

func verifyTenantClaim(ctx context.Context, verifyTenant bool, tenant string) error {

	l := log.FromContext(ctx)

	if verifyTenant {
		if tenant == "" {
			l.Errorf("No tenant claim in the token")
			return jwt.ErrTokenInvalid
		}
	} else if tenant != "" {
		l.Errorf("Unexpected tenant claim: %s in the token", tenant)
		return jwt.ErrTokenInvalid
	}

	return nil
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

	if token.Claims.Device != true {
		l.Errorf("not a device token")
		return jwt.ErrTokenInvalid
	}

	if err := verifyTenantClaim(ctx, d.verifyTenant, token.Claims.Tenant); err != nil {
		return err
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
		if err == store.ErrAuthSetNotFound {
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

func (d *DevAuth) GetLimit(ctx context.Context, name string) (*model.Limit, error) {
	lim, err := d.db.GetLimit(ctx, name)

	switch err {
	case nil:
		return lim, nil
	case store.ErrLimitNotFound:
		if name == model.LimitMaxDeviceCount {
			return &model.Limit{Name: name, Value: d.config.MaxDevicesLimitDefault}, nil
		}
		return &model.Limit{Name: name, Value: 0}, nil
	default:
		return nil, err
	}
}

func (d *DevAuth) GetTenantLimit(ctx context.Context, name, tenant_id string) (*model.Limit, error) {
	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: tenant_id,
	})

	return d.GetLimit(ctx, name)
}

// WithTenantVerification will force verification of tenant token with tenant
// administrator when processing device authentication requests. Returns an
// updated devauth.
func (d *DevAuth) WithTenantVerification(c tenant.ClientRunner) *DevAuth {
	d.cTenant = c
	d.verifyTenant = true
	return d
}

func (d *DevAuth) SetTenantLimit(ctx context.Context, tenant_id string, limit model.Limit) error {
	l := log.FromContext(ctx)

	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: tenant_id,
	})

	l.Infof("setting limit %v for tenant %v", limit, tenant_id)

	if err := d.db.PutLimit(ctx, limit); err != nil {
		l.Errorf("failed to save limit %v for tenant %v to database: %v",
			limit, tenant_id, err)
		return errors.Wrapf(err, "failed to save limit %v for tenant %v to database",
			limit, tenant_id)
	}
	return nil
}

func (d *DevAuth) GetDevCountByStatus(ctx context.Context, status string) (int, error) {
	return d.db.GetDevCountByStatus(ctx, status)
}

// canAcceptDevice checks if model.LimitMaxDeviceCount will be exceeded
func (d *DevAuth) canAcceptDevice(ctx context.Context) (bool, error) {
	limit, err := d.GetLimit(ctx, model.LimitMaxDeviceCount)
	if err != nil {
		return false, errors.Wrap(err, "can't get current device limit")
	}

	if limit.Value == 0 {
		return true, nil
	}

	accepted, err := d.db.GetDevCountByStatus(ctx, model.DevStatusAccepted)
	if err != nil {
		return false, errors.Wrap(err, "can't get current device count")
	}

	if uint64(accepted+1) <= limit.Value {
		return true, nil
	}

	return false, nil
}

func (d *DevAuth) DeleteTokens(ctx context.Context, tenant_id, device_id string) error {
	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: tenant_id,
	})

	var err error

	if device_id != "" {
		err = d.db.DeleteTokenByDevId(ctx, device_id)
	} else {
		err = d.db.DeleteTokens(ctx)
	}

	if err != nil && err != store.ErrTokenNotFound {
		return errors.Wrapf(err, "failed to delete tokens for tenant: %v, device id: %v", tenant_id, device_id)
	}

	return nil
}

func (d *DevAuth) ProvisionTenant(ctx context.Context, tenant_id string) error {
	tenantCtx := identity.WithContext(ctx, &identity.Identity{
		Tenant: tenant_id,
	})

	dbname := mstore.DbFromContext(tenantCtx, mongo.DbName)

	return d.db.WithAutomigrate().MigrateTenant(tenantCtx, dbname, mongo.DbVersion)
}

func (d *DevAuth) GetTenantDeviceStatus(ctx context.Context, tenantId, deviceId string) (*model.Status, error) {
	tenantCtx := identity.WithContext(ctx, &identity.Identity{
		Tenant: tenantId,
	})

	dev, err := d.db.GetDeviceById(tenantCtx, deviceId)
	switch err {
	case nil:
		return &model.Status{Status: dev.Status}, nil
	case store.ErrDevNotFound:
		return nil, ErrDeviceNotFound
	default:
		return nil, errors.Wrapf(err, "get device %s failed", deviceId)

	}
}
