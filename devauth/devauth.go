// Copyright 2020 Northern.tech AS
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
	"github.com/mendersoftware/deviceauth/client/inventory"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/mendersoftware/go-lib-micro/apiclient"
	ctxhttpheader "github.com/mendersoftware/go-lib-micro/context/httpheader"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/oid"
	"github.com/mendersoftware/go-lib-micro/plan"
	"github.com/mendersoftware/go-lib-micro/ratelimits"
	"github.com/mendersoftware/go-lib-micro/requestid"
	mstore "github.com/mendersoftware/go-lib-micro/store"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/mendersoftware/deviceauth/cache"
	"github.com/mendersoftware/deviceauth/client/orchestrator"
	"github.com/mendersoftware/deviceauth/client/tenant"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	"github.com/mendersoftware/deviceauth/store/mongo"
	"github.com/mendersoftware/deviceauth/utils"
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

	ErrInvalidDeviceID  = errors.New("invalid device ID type")
	ErrInvalidAuthSetID = errors.New("auth set id is not a valid ID")
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
//go:generate ../utils/mockgen.sh
type App interface {
	HealthCheck(ctx context.Context) error
	SubmitAuthRequest(ctx context.Context, r *model.AuthReq) (string, error)

	GetDevices(ctx context.Context, skip, limit uint, filter store.DeviceFilter) ([]model.Device, error)
	GetDevice(ctx context.Context, dev_id string) (*model.Device, error)
	DecommissionDevice(ctx context.Context, dev_id string) error
	DeleteAuthSet(ctx context.Context, dev_id string, auth_id string) error
	AcceptDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	RejectDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	ResetDeviceAuth(ctx context.Context, dev_id string, auth_id string) error
	PreauthorizeDevice(ctx context.Context, req *model.PreAuthReq) error

	RevokeToken(ctx context.Context, tokenID string) error
	VerifyToken(ctx context.Context, token string) error
	DeleteTokens(ctx context.Context, tenantID, deviceID string) error

	SetTenantLimit(ctx context.Context, tenant_id string, limit model.Limit) error
	DeleteTenantLimit(ctx context.Context, tenant_id string, limit string) error

	GetLimit(ctx context.Context, name string) (*model.Limit, error)
	GetTenantLimit(ctx context.Context, name, tenant_id string) (*model.Limit, error)

	GetDevCountByStatus(ctx context.Context, status string) (int, error)

	ProvisionTenant(ctx context.Context, tenant_id string) error

	GetTenantDeviceStatus(ctx context.Context, tenantId, deviceId string) (*model.Status, error)
}

type DevAuth struct {
	db           store.DataStore
	invClient    inventory.Client
	cOrch        orchestrator.ClientRunner
	cTenant      tenant.ClientRunner
	jwt          jwt.Handler
	clientGetter ApiClientGetter
	verifyTenant bool
	config       Config
	cache        cache.Cache
	clock        utils.Clock
}

type Config struct {
	// token issuer
	Issuer string
	// token expiration time
	ExpirationTime int64
	// Default tenant token to use when the client supplies none. Can be
	// empty
	DefaultTenantToken string
	InventoryAddr      string
}

func NewDevAuth(d store.DataStore, co orchestrator.ClientRunner,
	jwt jwt.Handler, config Config) *DevAuth {

	return &DevAuth{
		db:           d,
		invClient:    inventory.NewClient(config.InventoryAddr, false),
		cOrch:        co,
		jwt:          jwt,
		clientGetter: simpleApiClientGetter,
		verifyTenant: false,
		config:       config,
		clock:        utils.NewClock(),
	}
}

func (d *DevAuth) HealthCheck(ctx context.Context) error {
	err := d.db.Ping(ctx)
	if err != nil {
		return errors.Wrap(err, "error reaching MongoDB")
	}
	err = d.invClient.CheckHealth(ctx)
	if err != nil {
		return errors.Wrap(err, "Inventory service unhealthy")
	}
	err = d.cOrch.CheckHealth(ctx)
	if err != nil {
		return errors.Wrap(err, "Workflows service unhealthy")
	}
	if d.verifyTenant {
		err = d.cTenant.CheckHealth(ctx)
		if err != nil {
			return errors.Wrap(err, "Tenantadm service unhealthy")
		}
	}
	return nil
}

func (d *DevAuth) getDeviceFromAuthRequest(ctx context.Context, r *model.AuthReq, currentStatus *string) (*model.Device, error) {
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
	addDeviceErr := err
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

	idData := identity.FromContext(ctx)
	tenantId := ""
	if idData != nil {
		tenantId = idData.Tenant
	}
	if addDeviceErr != store.ErrObjectExists {
		d.invClient.SetDeviceIdentity(ctx, tenantId, dev.Id, dev.IdDataStruct)
	}

	if addDeviceErr == store.ErrObjectExists {
		*currentStatus = dev.Status
	}

	// check if the device is in the decommissioning state
	if dev.Decommissioning {
		l.Warnf("Device %s in the decommissioning state.", dev.Id)
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

func (d *DevAuth) doVerifyTenant(ctx context.Context, token string) (*tenant.Tenant, error) {
	t, err := d.cTenant.VerifyToken(ctx, token, d.clientGetter())

	if err != nil {
		if tenant.IsErrTokenVerificationFailed(err) {
			return nil, MakeErrDevAuthUnauthorized(err)
		}

		return nil, errors.Wrap(err, "request to verify tenant token failed")
	}

	return t, nil
}

func (d *DevAuth) getTenantWithDefault(ctx context.Context, tenantToken, defaultToken string) (context.Context, *tenant.Tenant, error) {
	l := log.FromContext(ctx)

	if tenantToken == "" && defaultToken == "" {
		return nil, nil, MakeErrDevAuthUnauthorized(errors.New("tenant token missing"))
	}

	var chosenToken string
	var t *tenant.Tenant
	var err error

	// try the provided token
	// but continue on errors and maybe try the default token
	if tenantToken != "" {
		t, err = d.doVerifyTenant(ctx, tenantToken)

		if err == nil {
			chosenToken = tenantToken
		} else {
			l.Errorf("Failed to verify supplied tenant token: %s", err.Error())
		}
	}

	// if we still haven't selected a tenant - the token didn't work
	// try the default one
	if t == nil && defaultToken != "" {
		t, err = d.doVerifyTenant(ctx, defaultToken)

		if err == nil {
			chosenToken = defaultToken
		}
		if err != nil {
			l.Errorf("Failed to verify default tenant token: %s", err.Error())
		}
	}

	// none of the tokens worked
	if err != nil {
		if tenant.IsErrTokenVerificationFailed(err) {
			return ctx, nil, MakeErrDevAuthUnauthorized(err)
		}
		return ctx, nil, err
	}

	// we do have a working token/valid tenant
	tCtx, err := tenantWithContext(ctx, chosenToken)
	if err != nil {
		l.Errorf("failed to setup tenant context: %v", err)
		return nil, nil, ErrDevAuthUnauthorized
	}

	return tCtx, t, nil
}

func (d *DevAuth) SubmitAuthRequest(ctx context.Context, r *model.AuthReq) (string, error) {
	l := log.FromContext(ctx)

	var tenant *tenant.Tenant
	var err error

	if d.verifyTenant {
		ctx, tenant, err = d.getTenantWithDefault(ctx, r.TenantToken, d.config.DefaultTenantToken)
		if err != nil {
			return "", err
		}
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

	// request was already present in DB, check its status
	if authSet.Status == model.DevStatusAccepted {
		jti := oid.FromString(authSet.Id)
		if jti.String() == "" {
			return "", ErrInvalidAuthSetID
		}
		sub := oid.FromString(authSet.DeviceId)
		if sub.String() == "" {
			return "", ErrInvalidDeviceID
		}
		now := time.Now()
		token := &jwt.Token{Claims: jwt.Claims{
			ID:      jti,
			Subject: sub,
			Issuer:  d.config.Issuer,
			ExpiresAt: jwt.Time{
				Time: now.Add(time.Second *
					time.Duration(d.config.ExpirationTime)),
			},
			IssuedAt: jwt.Time{Time: now},
			Device:   true,
		}}

		if d.verifyTenant {
			ident := identity.FromContext(ctx)
			if ident != nil && ident.Tenant != "" {
				token.Claims.Tenant = ident.Tenant
				token.Claims.Plan = tenant.Plan
			}
		} else {
			token.Claims.Plan = plan.PlanEnterprise
		}

		// sign and encode as JWT
		raw, err := token.MarshalJWT(d.signToken(ctx))
		if err != nil {
			return "", errors.Wrap(err, "generate token error")
		}

		if err := d.db.AddToken(ctx, token); err != nil {
			return "", errors.Wrap(err, "add token error")
		}

		l.Infof("Token %s assigned to device %s",
			token.Claims.ID, token.Claims.Subject)
		return string(raw), nil
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

	currentStatus := dev.Status
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
	update := model.AuthSetUpdate{
		Status: model.DevStatusAccepted,
	}
	// persist the 'accepted' status in both auth set, and device
	if err := d.db.UpdateAuthSetById(ctx, aset.Id, update); err != nil {
		return nil, errors.Wrap(err, "failed to update auth set status")
	}

	if err := d.updateDeviceStatus(ctx, aset.DeviceId, model.DevStatusAccepted, currentStatus); err != nil {
		return nil, err
	}

	aset.Status = model.DevStatusAccepted
	return aset, nil
}

func (d *DevAuth) updateDeviceStatus(ctx context.Context, devId, status string, currentStatus string) error {
	statusChanged := true
	newStatus, err := d.db.GetDeviceStatus(ctx, devId)
	if currentStatus == newStatus {
		statusChanged = false
	}
	if status == "" {
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

	b, err := json.Marshal([]string{devId})
	if err != nil {
		return errors.New("internal error: cannot marshal array into json")
	}
	// submit device status change job
	if statusChanged {
		tenantId := ""
		idData := identity.FromContext(ctx)
		if idData != nil {
			tenantId = idData.Tenant
		}
		if err := d.cOrch.SubmitUpdateDeviceStatusJob(
			ctx,
			orchestrator.UpdateDeviceStatusReq{
				RequestId: requestid.FromContext(ctx),
				Ids:       string(b), // []string{devId},
				TenantId:  tenantId,
				Status:    status,
			}); err != nil {
			return errors.Wrap(err, "update device status job error")
		}
	}
	return nil
}

// processAuthRequest will process incoming auth request and record authentication
// data information it contains. Returns a tupe (auth set, error). If no errors were
// present, model.AuthSet.Status will indicate the status of device admission
func (d *DevAuth) processAuthRequest(ctx context.Context, r *model.AuthReq) (*model.AuthSet, error) {

	l := log.FromContext(ctx)

	var currentState string
	currentState = ""
	// get device associated with given authorization request
	dev, err := d.getDeviceFromAuthRequest(ctx, r, &currentState)
	if err != nil {
		return nil, err
	}

	idDataStruct, idDataSha256, err := parseIdData(r.IdData)
	if err != nil {
		return nil, MakeErrDevAuthBadRequest(err)
	}

	areq := &model.AuthSet{
		Id:           oid.NewUUIDv4().String(),
		IdData:       r.IdData,
		IdDataStruct: idDataStruct,
		IdDataSha256: idDataSha256,
		PubKey:       r.PubKey,
		DeviceId:     dev.Id,
		Status:       model.DevStatusPending,
		Timestamp:    uto.TimePtr(time.Now()),
	}

	// record authentication request
	err = d.db.AddAuthSet(ctx, *areq)
	if err != nil && err != store.ErrObjectExists {
		return nil, err
	}

	// update the device status
	if err := d.updateDeviceStatus(ctx, dev.Id, "", currentState); err != nil {
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
func (d *DevAuth) DecommissionDevice(ctx context.Context, devID string) error {

	l := log.FromContext(ctx)

	l.Warnf("Decommission device with id: %s", devID)

	err := d.cacheDeleteToken(ctx, devID)
	if err != nil {
		return errors.Wrapf(err, "failed to delete token for %s from cache", devID)
	}

	// set decommissioning flag on the device
	updev := model.DeviceUpdate{
		Decommissioning: to.BoolPtr(true),
	}
	if err := d.db.UpdateDevice(
		ctx, model.Device{Id: devID}, updev,
	); err != nil {
		return err
	}

	reqId := requestid.FromContext(ctx)

	// submit device decommissioning job
	if err := d.cOrch.SubmitDeviceDecommisioningJob(
		ctx,
		orchestrator.DecommissioningReq{
			DeviceId:      devID,
			RequestId:     reqId,
			Authorization: ctxhttpheader.FromContext(ctx, "Authorization"),
		}); err != nil {
		return errors.Wrap(err, "submit device decommissioning job error")
	}

	// delete device authorization sets
	if err := d.db.DeleteAuthSetsForDevice(ctx, devID); err != nil && err != store.ErrAuthSetNotFound {
		return errors.Wrap(err, "db delete device authorization sets error")
	}

	devOID := oid.FromString(devID)
	// If the devID is not a valid string, there's no token.
	if devOID.String() == "" {
		return ErrInvalidDeviceID
	}
	// delete device tokens
	if err := d.db.DeleteTokenByDevId(
		ctx, devOID,
	); err != nil && err != store.ErrTokenNotFound {
		return errors.Wrap(err, "db delete device tokens error")
	}

	// delete device
	return d.db.DeleteDevice(ctx, devID)
}

// Deletes device authentication set, and optionally the device.
func (d *DevAuth) DeleteAuthSet(ctx context.Context, devID string, authId string) error {

	l := log.FromContext(ctx)

	l.Warnf("Delete authentication set with id: "+
		"%s for the device with id: %s",
		authId, devID)

	err := d.cacheDeleteToken(ctx, devID)
	if err != nil {
		return errors.Wrapf(err, "failed to delete token for %s from cache", devID)
	}

	// retrieve device authentication set to check its status
	authSet, err := d.db.GetAuthSetById(ctx, authId)
	if err != nil {
		if err == store.ErrAuthSetNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	// delete device authorization set
	if err := d.db.DeleteAuthSetForDevice(ctx, devID, authId); err != nil {
		return err
	}

	// if the device authentication set is accepted delete device tokens
	if authSet.Status == model.DevStatusAccepted {
		// If string is not a valid UUID there's no token.
		devOID := oid.FromString(devID)
		if err := d.db.DeleteTokenByDevId(
			ctx, devOID,
		); err != nil && err != store.ErrTokenNotFound {
			return errors.Wrap(err,
				"db delete device tokens error")
		}
	} else if authSet.Status == model.DevStatusPreauth {
		// only delete the device if the set is 'preauthorized'
		// otherwise device data may live in other services too,
		// and is a case for decommissioning
		err = d.db.DeleteDevice(ctx, devID)
		if err != nil {
			return err
		}
		tenantId := ""
		idData := identity.FromContext(ctx)
		if idData != nil {
			tenantId = idData.Tenant
		}
		b, err := json.Marshal([]string{devID})
		if err != nil {
			return errors.New("internal error: cannot marshal array into json")
		}
		if err = d.cOrch.SubmitUpdateDeviceStatusJob(
			ctx,
			orchestrator.UpdateDeviceStatusReq{
				RequestId: requestid.FromContext(ctx),
				Ids:       string(b), // []string{dev.Id},
				TenantId:  tenantId,
				Status:    "decommissioned",
			}); err != nil {
			return errors.Wrap(err, "update device status job error")
		}
		return err
	}

	return d.updateDeviceStatus(ctx, devID, "", authSet.Status)
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

func (d *DevAuth) setAuthSetStatus(
	ctx context.Context,
	deviceID string,
	authID string,
	status string,
) error {
	aset, err := d.db.GetAuthSetById(ctx, authID)
	if err != nil {
		if err == store.ErrAuthSetNotFound {
			return err
		}
		return errors.Wrap(err, "db get auth set error")
	}

	if aset.DeviceId != deviceID {
		return ErrDevIdAuthIdMismatch
	}

	if aset.Status == status {
		return nil
	}

	currentStatus := aset.Status

	if aset.Status == model.DevStatusAccepted && (status == model.DevStatusRejected || status == model.DevStatusPending) {
		deviceOID := oid.FromString(aset.DeviceId)
		// delete device token
		err := d.db.DeleteTokenByDevId(ctx, deviceOID)
		if err != nil && err != store.ErrTokenNotFound {
			return errors.Wrap(err, "db delete device token error")
		}
	}

	// if accepting an auth set
	if status == model.DevStatusAccepted {
		// reject all accepted auth sets for this device first
		if err := d.db.UpdateAuthSet(ctx,
			bson.M{
				model.AuthSetKeyDeviceId: deviceID,
				"$or": []bson.M{
					{model.AuthSetKeyStatus: model.DevStatusAccepted},
					{model.AuthSetKeyStatus: model.DevStatusPreauth},
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
		return d.updateDeviceStatus(ctx, deviceID, status, currentStatus)
	}
	return d.updateDeviceStatus(ctx, deviceID, "", currentStatus)
}

func (d *DevAuth) RejectDeviceAuth(ctx context.Context, device_id string, auth_id string) error {
	err := d.cacheDeleteToken(ctx, device_id)
	if err != nil {
		return errors.Wrapf(err, "failed to delete token for %s from cache", device_id)
	}

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

	// submit device status change job
	b, err := json.Marshal([]string{dev.Id})
	if err != nil {
		return errors.New("internal error: cannot marshal array into json")
	}

	tenantId := ""
	idData := identity.FromContext(ctx)
	if idData != nil {
		tenantId = idData.Tenant
	}

	d.invClient.SetDeviceIdentity(ctx, tenantId, dev.Id, dev.IdDataStruct)

	if err = d.cOrch.SubmitUpdateDeviceStatusJob(
		ctx,
		orchestrator.UpdateDeviceStatusReq{
			RequestId: requestid.FromContext(ctx),
			Ids:       string(b), // []string{dev.Id},
			TenantId:  tenantId,
			Status:    dev.Status,
		}); err != nil {
		return errors.Wrap(err, "update device status job error")
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
		d.invClient.SetDeviceIdentity(ctx, tenantId, req.DeviceId, idDataStruct)
		return nil
	case store.ErrObjectExists:
		return ErrDeviceExists
	default:
		return errors.Wrap(err, "failed to add auth set")
	}
}

func (d *DevAuth) RevokeToken(ctx context.Context, tokenID string) error {

	l := log.FromContext(ctx)
	tokenOID := oid.FromString(tokenID)

	if d.cache != nil {
		token, err := d.db.GetToken(ctx, tokenOID)
		if err != nil {
			return err
		}
		err = d.cacheDeleteToken(ctx, token.Claims.Subject.String())
		if err != nil {
			return errors.Wrapf(err, "failed to delete token for %s from cache", token.Claims.Subject.String())
		}
	}

	l.Warnf("Revoke token with jti: %s", tokenID)
	return d.db.DeleteToken(ctx, tokenOID)
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
		if err == jwt.ErrTokenExpired && jti.String() != "" {
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

	origMethod := ctxhttpheader.FromContext(ctx, "X-Forwarded-Method")
	origUri := ctxhttpheader.FromContext(ctx, "X-Forwarded-Uri")
	origUri = purgeUriArgs(origUri)

	// throttle and try fetch token from cache - if cached, it was
	// already verified against the db checks below, we trust it
	cachedToken, err := d.cacheThrottleVerify(ctx, token, raw, origMethod, origUri)

	if err == cache.ErrTooManyRequests {
		return err
	}

	if cachedToken != "" {
		return nil
	}

	// caching is best effort, don't fail
	if err != nil {
		l.Errorf("Failed to throttle for token %v: %s, continue.", token, err.Error())
	}

	// cache check was a MISS, hit the db for verification
	// check if token is in the system
	_, err = d.db.GetToken(ctx, jti)
	if err != nil {
		if err == store.ErrTokenNotFound {
			l.Errorf("Token %s not found", jti)
			return err
		}
		return errors.Wrapf(err, "Cannot get token with id: %s from database: %s", jti, err)
	}

	auth, err := d.db.GetAuthSetById(ctx, jti.String())
	if err != nil {
		if err == store.ErrAuthSetNotFound {
			l.Errorf("Token %s not found", jti)
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

	// after successful token verification - cache it (best effort)
	_ = d.cacheSetToken(ctx, token, raw)

	return nil
}

// purgeUriArgs removes query string args from an uri string
// important for burst control (bursts are per uri without args)
func purgeUriArgs(uri string) string {
	return strings.Split(uri, "?")[0]
}

func (d *DevAuth) cacheThrottleVerify(ctx context.Context, token *jwt.Token, originalRaw, origMethod, origUri string) (string, error) {
	if d.cache == nil {
		return "", nil
	}

	// try get cached/precomputed limits
	limits, err := d.getApiLimits(ctx,
		token.Claims.Tenant,
		token.Claims.Subject.String())

	if err != nil {
		return "", err
	}

	// apply throttling and fetch cached token
	cached, err := d.cache.Throttle(ctx,
		originalRaw,
		*limits,
		token.Claims.Tenant,
		token.Claims.Subject.String(),
		cache.IdTypeDevice,
		origUri,
		origMethod)

	return cached, err
}

func (d *DevAuth) cacheSetToken(ctx context.Context, token *jwt.Token, raw string) error {
	if d.cache == nil {
		return nil
	}

	expireIn := time.Duration(token.Claims.ExpiresAt.Unix()-d.clock.Now().Unix()) * time.Second

	return d.cache.CacheToken(ctx,
		token.Claims.Tenant,
		token.Claims.Subject.String(),
		cache.IdTypeDevice,
		raw,
		expireIn)
}

func (d *DevAuth) getApiLimits(ctx context.Context, tid, did string) (*ratelimits.ApiLimits, error) {
	limits, err := d.cache.GetLimits(ctx, tid, did, cache.IdTypeDevice)
	if err != nil {
		return nil, err
	}

	if limits != nil {
		return limits, nil
	}

	dev, err := d.db.GetDeviceById(ctx, did)
	if err != nil {
		return nil, err
	}

	t, err := d.cTenant.GetTenant(ctx, tid, d.clientGetter())
	if err != nil {
		return nil, errors.Wrap(err, "request to get tenant failed")
	}
	if t == nil {
		return nil, errors.New("tenant not found")
	}

	finalLimits := apiLimitsOverride(t.ApiLimits.DeviceLimits, dev.ApiLimits)

	err = d.cache.CacheLimits(ctx, finalLimits, tid, did, cache.IdTypeDevice)

	return &finalLimits, err
}

func (d *DevAuth) cacheDeleteToken(ctx context.Context, did string) error {
	if d.cache == nil {
		return nil
	}

	idData := identity.FromContext(ctx)
	if idData == nil {
		return errors.New("can't unpack tenant identity data from context")
	}
	tid := idData.Tenant

	return d.cache.DeleteToken(ctx, tid, did, cache.IdTypeDevice)
}

// TODO move to 'ratelimits', as ApiLimits methods maybe?
func apiLimitsOverride(src, dest ratelimits.ApiLimits) ratelimits.ApiLimits {
	// override only if not default
	if dest.ApiQuota.MaxCalls != 0 && dest.ApiQuota.IntervalSec != 0 {
		src.ApiQuota.MaxCalls = dest.ApiQuota.MaxCalls
		src.ApiQuota.IntervalSec = dest.ApiQuota.IntervalSec
	}

	out := make([]ratelimits.ApiBurst, len(src.ApiBursts))
	copy(out, src.ApiBursts)

	for _, bdest := range dest.ApiBursts {
		found := false
		for i, bsrc := range src.ApiBursts {
			if bdest.Action == bsrc.Action &&
				bdest.Uri == bsrc.Uri {
				out[i].MinIntervalSec = bdest.MinIntervalSec
				found = true
			}
		}

		if !found {
			out = append(out,
				ratelimits.ApiBurst{
					Action:         bdest.Action,
					Uri:            bdest.Uri,
					MinIntervalSec: bdest.MinIntervalSec},
			)
		}
	}

	src.ApiBursts = out
	return src
}

func (d *DevAuth) GetLimit(ctx context.Context, name string) (*model.Limit, error) {
	lim, err := d.db.GetLimit(ctx, name)

	switch err {
	case nil:
		return lim, nil
	case store.ErrLimitNotFound:
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

func (d *DevAuth) WithCache(c cache.Cache) *DevAuth {
	d.cache = c
	return d
}

func (d *DevAuth) WithClock(c utils.Clock) *DevAuth {
	d.clock = c
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

func (d *DevAuth) DeleteTenantLimit(ctx context.Context, tenant_id string, limit string) error {
	l := log.FromContext(ctx)

	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: tenant_id,
	})

	l.Infof("removing limit %v for tenant %v", limit, tenant_id)

	if err := d.db.DeleteLimit(ctx, limit); err != nil {
		l.Errorf("failed to delete limit %v for tenant %v to database: %v",
			limit, tenant_id, err)
		return errors.Wrapf(err, "failed to delete limit %v for tenant %v to database",
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

func (d *DevAuth) DeleteTokens(
	ctx context.Context,
	tenantID string,
	deviceID string,
) error {
	var err error
	ctx = identity.WithContext(ctx, &identity.Identity{
		Tenant: tenantID,
	})

	if deviceID != "" {
		deviceOID := oid.FromString(deviceID)
		if deviceOID.String() == "" {
			return ErrInvalidAuthSetID
		}
		err = d.db.DeleteTokenByDevId(ctx, deviceOID)
	} else {
		if err := d.cacheFlush(ctx); err != nil {
			return errors.Wrapf(err, "failed to flush cache when cleaning tokens for tenant %v", tenantID)
		}

		err = d.db.DeleteTokens(ctx)
	}

	if err != nil && err != store.ErrTokenNotFound {
		return errors.Wrapf(err, "failed to delete tokens for tenant: %v, device id: %v", tenantID, deviceID)
	}

	return nil
}

func (d *DevAuth) cacheFlush(ctx context.Context) error {
	if d.cache == nil {
		return nil
	}

	return d.cache.FlushDB(ctx)
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
