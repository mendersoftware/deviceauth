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
package http

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mendersoftware/go-lib-micro/identity"

	"github.com/ant0ine/go-json-rest/rest"
	ctxhttpheader "github.com/mendersoftware/go-lib-micro/context/httpheader"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/devauth"
	"github.com/mendersoftware/deviceauth/jwt"
	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/store"
	"github.com/mendersoftware/deviceauth/utils"
)

const (
	uriAuthReqs = "/api/devices/v1/authentication/auth_requests"

	// internal API
	uriTokenVerify        = "/api/internal/v1/devauth/tokens/verify"
	uriTenantLimit        = "/api/internal/v1/devauth/tenant/:id/limits/:name"
	uriTokens             = "/api/internal/v1/devauth/tokens"
	uriTenants            = "/api/internal/v1/devauth/tenants"
	uriTenantDeviceStatus = "/api/internal/v1/devauth/tenants/:tid/devices/:did/status"
	uriTenantDevices      = "/api/internal/v1/devauth/tenants/:tid/devices"

	// management API v2
	v2uriDevices             = "/api/management/v2/devauth/devices"
	v2uriDevicesCount        = "/api/management/v2/devauth/devices/count"
	v2uriDevice              = "/api/management/v2/devauth/devices/:id"
	v2uriDeviceAuthSet       = "/api/management/v2/devauth/devices/:id/auth/:aid"
	v2uriDeviceAuthSetStatus = "/api/management/v2/devauth/devices/:id/auth/:aid/status"
	v2uriToken               = "/api/management/v2/devauth/tokens/:id"
	v2uriDevicesLimit        = "/api/management/v2/devauth/limits/:name"

	HdrAuthReqSign = "X-MEN-Signature"
)

var (
	ErrIncorrectStatus = errors.New("incorrect device status")
	ErrNoAuthHeader    = errors.New("no authorization header")

	DevStatuses = []string{model.DevStatusPending, model.DevStatusRejected, model.DevStatusAccepted, model.DevStatusPreauth}
)

type DevAuthApiHandlers struct {
	devAuth devauth.App
	db      store.DataStore
}

type DevAuthApiStatus struct {
	Status string `json:"status"`
}

func NewDevAuthApiHandlers(devAuth devauth.App, db store.DataStore) ApiHandler {
	return &DevAuthApiHandlers{
		devAuth: devAuth,
		db:      db,
	}
}

func (d *DevAuthApiHandlers) GetApp() (rest.App, error) {
	routes := []*rest.Route{
		rest.Post(uriAuthReqs, d.SubmitAuthRequestHandler),
		rest.Get(uriTokenVerify, d.VerifyTokenHandler),
		rest.Post(uriTokenVerify, d.VerifyTokenHandler),
		rest.Delete(uriTokens, d.DeleteTokensHandler),

		rest.Put(uriTenantLimit, d.PutTenantLimitHandler),
		rest.Get(uriTenantLimit, d.GetTenantLimitHandler),

		rest.Post(uriTenants, d.ProvisionTenantHandler),
		rest.Get(uriTenantDeviceStatus, d.GetTenantDeviceStatus),
		rest.Get(uriTenantDevices, d.GetTenantDevicesHandler),

		// API v2
		rest.Get(v2uriDevicesCount, d.GetDevicesCountHandler),
		rest.Get(v2uriDevices, d.GetDevicesV2Handler),
		rest.Post(v2uriDevices, d.PostDevicesV2Handler),
		rest.Get(v2uriDevice, d.GetDeviceV2Handler),
		rest.Delete(v2uriDevice, d.DeleteDeviceHandler),
		rest.Delete(v2uriDeviceAuthSet, d.DeleteDeviceAuthSetHandler),
		rest.Put(v2uriDeviceAuthSetStatus, d.UpdateDeviceStatusHandler),
		rest.Get(v2uriDeviceAuthSetStatus, d.GetAuthSetStatusHandler),
		rest.Delete(v2uriToken, d.DeleteTokenHandler),
		rest.Get(v2uriDevicesLimit, d.GetLimitHandler),
	}

	app, err := rest.MakeRouter(
		// augment routes with OPTIONS handler
		AutogenOptionsRoutes(routes, AllowHeaderOptionsGenerator)...,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create router")
	}

	return app, nil
}

func (d *DevAuthApiHandlers) SubmitAuthRequestHandler(w rest.ResponseWriter, r *rest.Request) {
	var authreq model.AuthReq

	ctx := r.Context()

	l := log.FromContext(ctx)

	//validate req body by reading raw content manually
	//(raw body will be needed later, DecodeJsonPayload would
	//unmarshal and close it)
	body, err := utils.ReadBodyRaw(r)
	if err != nil {
		err = errors.Wrap(err, "failed to decode auth request")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &authreq)
	if err != nil {
		err = errors.Wrap(err, "failed to decode auth request")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err = authreq.Validate()
	if err != nil {
		err = errors.Wrap(err, "invalid auth request")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	//verify signature
	signature := r.Header.Get(HdrAuthReqSign)
	if signature == "" {
		rest_utils.RestErrWithLog(w, r, l, errors.New("missing request signature header"), http.StatusBadRequest)
		return
	}

	err = utils.VerifyAuthReqSign(signature, authreq.PubKeyStruct, body)
	if err != nil {
		rest_utils.RestErrWithLogMsg(w, r, l, err, http.StatusUnauthorized, "signature verification failed")
		return
	}

	token, err := d.devAuth.SubmitAuthRequest(ctx, &authreq)

	if err != nil {
		if devauth.IsErrDevAuthUnauthorized(err) {
			rest_utils.RestErrWithWarningMsg(w, r, l, err,
				http.StatusUnauthorized, errors.Cause(err).Error())
			return
		} else if devauth.IsErrDevAuthBadRequest(err) {
			rest_utils.RestErrWithWarningMsg(w, r, l, err,
				http.StatusBadRequest, errors.Cause(err).Error())
			return
		}
	}

	switch err {
	case devauth.ErrDevIdAuthIdMismatch, devauth.ErrMaxDeviceCountReached:
		// error is always set to unauthorized, client does not need to
		// know why
		rest_utils.RestErrWithWarningMsg(w, r, l, devauth.ErrDevAuthUnauthorized,
			http.StatusUnauthorized, "unauthorized")
		return
	case nil:
		w.(http.ResponseWriter).Write([]byte(token))
		w.Header().Set("Content-Type", "application/jwt")
		return
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}
}

func (d *DevAuthApiHandlers) PostDevicesV2Handler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	req, err := parsePreAuthReq(r.Body)
	if err != nil {
		err = errors.Wrap(err, "failed to decode preauth request")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	reqDbModel, err := req.getDbModel()
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	err = d.devAuth.PreauthorizeDevice(ctx, reqDbModel)
	switch err {
	case nil:
		w.Header().Set("Location", "devices/"+reqDbModel.DeviceId)
		w.WriteHeader(http.StatusCreated)
	case devauth.ErrDeviceExists:
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusConflict)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}
}

func (d *DevAuthApiHandlers) GetDevicesV2Handler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	page, perPage, err := rest_utils.ParsePagination(r)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	status, err := rest_utils.ParseQueryParmStr(r, model.DevKeyStatus, false, DevStatuses)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	skip := (page - 1) * perPage
	limit := perPage + 1
	devs, err := d.devAuth.GetDevices(ctx, uint(skip), uint(limit),
		store.DeviceFilter{Status: status})
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	len := len(devs)
	hasNext := false
	if uint64(len) > perPage {
		hasNext = true
		len = int(perPage)
	}

	links := rest_utils.MakePageLinkHdrs(r, page, perPage, hasNext)

	for _, l := range links {
		w.Header().Add("Link", l)
	}

	outDevs, err := devicesV2FromDbModel(devs[:len])
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteJson(outDevs)
}

func (d *DevAuthApiHandlers) GetDevicesCountHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	status := r.URL.Query().Get("status")

	switch status {
	case model.DevStatusAccepted,
		model.DevStatusRejected,
		model.DevStatusPending,
		model.DevStatusPreauth,
		"":
	default:
		rest_utils.RestErrWithLog(w, r, l, errors.New("status must be one of: pending, accepted, rejected, preauthorized"), http.StatusBadRequest)
		return
	}

	count, err := d.devAuth.GetDevCountByStatus(ctx, status)

	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteJson(model.Count{Count: count})
}

func (d *DevAuthApiHandlers) GetDeviceV2Handler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	devId := r.PathParam("id")

	dev, err := d.devAuth.GetDevice(ctx, devId)
	switch {
	case err == store.ErrDevNotFound:
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusNotFound)
	case dev != nil:
		apiDev, _ := deviceV2FromDbModel(dev)
		w.WriteJson(apiDev)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}
}

func (d *DevAuthApiHandlers) DeleteDeviceHandler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	devId := r.PathParam("id")

	if err := d.devAuth.DecommissionDevice(ctx, devId); err != nil {
		if err == store.ErrDevNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthApiHandlers) DeleteDeviceAuthSetHandler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	devId := r.PathParam("id")
	authId := r.PathParam("aid")

	if err := d.devAuth.DeleteAuthSet(ctx, devId, authId); err != nil {
		if err == store.ErrAuthSetNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthApiHandlers) DeleteTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	tokenID := r.PathParam("id")
	err := d.devAuth.RevokeToken(ctx, tokenID)
	if err != nil {
		if err == store.ErrTokenNotFound ||
			err == devauth.ErrInvalidAuthSetID {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthApiHandlers) VerifyTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	tokenStr, err := extractToken(r.Header)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, ErrNoAuthHeader, http.StatusUnauthorized)
		return
	}

	ctx = ctxhttpheader.WithContext(ctx,
		r.Header,
		"X-Original-Method",
		"X-Original-URI")

	// verify token
	err = d.devAuth.VerifyToken(ctx, tokenStr)
	code := http.StatusOK
	if err != nil {
		switch err {
		case jwt.ErrTokenExpired:
			code = http.StatusForbidden
		case store.ErrTokenNotFound, jwt.ErrTokenInvalid:
			code = http.StatusUnauthorized
		default:
			rest_utils.RestErrWithLogInternal(w, r, l, err)
			return
		}
		l.Error(err)
	}

	w.WriteHeader(code)
}

func (d *DevAuthApiHandlers) UpdateDeviceStatusHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	devid := r.PathParam("id")
	authid := r.PathParam("aid")

	var status DevAuthApiStatus
	err := r.DecodeJsonPayload(&status)
	if err != nil {
		err = errors.Wrap(err, "failed to decode status data")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	if err := statusValidate(&status); err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	if status.Status == model.DevStatusAccepted {
		err = d.devAuth.AcceptDeviceAuth(ctx, devid, authid)
	} else if status.Status == model.DevStatusRejected {
		err = d.devAuth.RejectDeviceAuth(ctx, devid, authid)
	} else if status.Status == model.DevStatusPending {
		err = d.devAuth.ResetDeviceAuth(ctx, devid, authid)
	}
	if err != nil {
		switch err {
		case store.ErrDevNotFound, store.ErrAuthSetNotFound:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusNotFound)
		case devauth.ErrDevIdAuthIdMismatch:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		case devauth.ErrMaxDeviceCountReached:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)

		default:
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type LimitValue struct {
	Limit uint64 `json:"limit"`
}

func (d *DevAuthApiHandlers) PutTenantLimitHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	tenantId := r.PathParam("id")
	reqLimitName := r.PathParam("name")

	if !model.IsValidLimit(reqLimitName) {
		rest_utils.RestErrWithLog(w, r, l,
			errors.Errorf("unsupported limit %v", reqLimitName),
			http.StatusBadRequest)
		return
	}

	var value LimitValue
	err := r.DecodeJsonPayload(&value)
	if err != nil {
		err = errors.Wrap(err, "failed to decode limit request")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	limit := model.Limit{
		Value: value.Limit,
		Name:  reqLimitName,
	}

	if err := d.devAuth.SetTenantLimit(ctx, tenantId, limit); err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthApiHandlers) GetTenantLimitHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	tenantId := r.PathParam("id")
	limitName := r.PathParam("name")

	if !model.IsValidLimit(limitName) {
		rest_utils.RestErrWithLog(w, r, l,
			errors.Errorf("unsupported limit %v", limitName),
			http.StatusBadRequest)
		return
	}

	lim, err := d.devAuth.GetTenantLimit(ctx, limitName, tenantId)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteJson(LimitValue{lim.Value})
}

func (d *DevAuthApiHandlers) GetLimitHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	name := r.PathParam("name")

	if !model.IsValidLimit(name) {
		rest_utils.RestErrWithLog(w, r, l,
			errors.Errorf("unsupported limit %v", name),
			http.StatusBadRequest)
		return
	}

	lim, err := d.devAuth.GetLimit(ctx, name)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteJson(LimitValue{lim.Value})
}

func (d *DevAuthApiHandlers) DeleteTokensHandler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	tenantId := r.URL.Query().Get("tenant_id")
	if tenantId == "" {
		rest_utils.RestErrWithLog(w, r, l, errors.New("tenant_id must be provided"), http.StatusBadRequest)
		return
	}
	devId := r.URL.Query().Get("device_id")

	err := d.devAuth.DeleteTokens(ctx, tenantId, devId)
	switch err {
	case nil:
		w.WriteHeader(http.StatusNoContent)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}
}

func (d *DevAuthApiHandlers) GetAuthSetStatusHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	devid := r.PathParam("id")
	authid := r.PathParam("aid")

	// get authset directly from store
	aset, err := d.db.GetAuthSetById(ctx, authid)
	switch err {
	case nil:
		w.WriteJson(&model.Status{Status: aset.Status})
	case store.ErrDevNotFound, store.ErrAuthSetNotFound:
		rest_utils.RestErrWithLog(w, r, l, store.ErrAuthSetNotFound, http.StatusNotFound)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l,
			errors.Wrapf(err,
				"failed to fetch auth set %s for device %s",
				authid, devid))
	}
}

func (d *DevAuthApiHandlers) ProvisionTenantHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	defer r.Body.Close()

	tenant, err := model.ParseNewTenant(r.Body)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err = d.devAuth.ProvisionTenant(ctx, tenant.TenantId)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (d *DevAuthApiHandlers) GetTenantDeviceStatus(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	tid := r.PathParam("tid")
	did := r.PathParam("did")

	if tid == "" {
		rest_utils.RestErrWithLog(w, r, l, errors.New("tenant id (tid) cannot be empty"), http.StatusBadRequest)
		return
	}

	if did == "" {
		rest_utils.RestErrWithLog(w, r, l, errors.New("device id (did) cannot be empty"), http.StatusBadRequest)
		return
	}

	status, err := d.devAuth.GetTenantDeviceStatus(ctx, tid, did)
	switch err {
	case nil:
		w.WriteJson(status)
	case devauth.ErrDeviceNotFound:
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusNotFound)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}
}

func (d *DevAuthApiHandlers) GetTenantDevicesHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	tid := r.PathParam("tid")
	if tid == "" {
		rest_utils.RestErrWithLog(w, r, l, errors.New("tenant id (tid) cannot be empty"), http.StatusBadRequest)
		return
	}
	// Inject tenant id into the request context
	ctx = identity.WithContext(ctx, &identity.Identity{Tenant: tid})
	r.Request = r.WithContext(ctx)

	d.GetDevicesV2Handler(w, r)
}

// Validate status.
// Expected statuses:
// - "accepted"
// - "rejected"
// - "pending"
func statusValidate(status *DevAuthApiStatus) error {
	if status.Status != model.DevStatusAccepted &&
		status.Status != model.DevStatusRejected &&
		status.Status != model.DevStatusPending {
		return ErrIncorrectStatus
	} else {
		return nil
	}
}

// extracts JWT from authorization header
func extractToken(header http.Header) (string, error) {
	const authHeaderName = "Authorization"
	authHeader := header.Get(authHeaderName)
	if authHeader == "" {
		return "", ErrNoAuthHeader
	}
	tokenStr := strings.Replace(authHeader, "Bearer", "", 1)
	tokenStr = strings.Replace(tokenStr, "bearer", "", 1)
	return strings.TrimSpace(tokenStr), nil
}
