// Copyright 2018 Northern.tech AS
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

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/globalsign/mgo/bson"
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

	uriDevices       = "/api/management/v1/devauth/devices"
	uriDevicesCount  = "/api/management/v1/devauth/devices/count"
	uriDevice        = "/api/management/v1/devauth/devices/:id"
	uriToken         = "/api/management/v1/devauth/tokens/:id"
	uriDeviceAuthSet = "/api/management/v1/devauth/devices/:id/auth/:aid"
	uriDeviceStatus  = "/api/management/v1/devauth/devices/:id/auth/:aid/status"
	uriLimit         = "/api/management/v1/devauth/limits/:name"

	// internal API
	uriTokenVerify        = "/api/internal/v1/devauth/tokens/verify"
	uriTenantLimit        = "/api/internal/v1/devauth/tenant/:id/limits/:name"
	uriTokens             = "/api/internal/v1/devauth/tokens"
	uriTenants            = "/api/internal/v1/devauth/tenants"
	uriTenantDeviceStatus = "/api/internal/v1/devauth/tenants/:tid/devices/:did/status"

	// migrated devadm api
	uriDevadmAuthSetStatus = "/api/management/v1/admission/devices/:aid/status"
	uriDevadmDevices       = "/api/management/v1/admission/devices"
	uriDevadmDevice        = "/api/management/v1/admission/devices/:aid"

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

		rest.Get(uriDevices, d.GetDevicesHandler),

		rest.Post(uriDevices, d.PreauthDeviceHandler),

		rest.Get(uriDevicesCount, d.GetDevicesCountHandler),

		rest.Get(uriDevice, d.GetDeviceHandler),

		rest.Delete(uriDevice, d.DeleteDeviceHandler),

		rest.Delete(uriDeviceAuthSet, d.DeleteDeviceAuthSetHandler),

		rest.Delete(uriToken, d.DeleteTokenHandler),

		rest.Post(uriTokenVerify, d.VerifyTokenHandler),

		rest.Delete(uriTokens, d.DeleteTokensHandler),

		rest.Put(uriDeviceStatus, d.UpdateDeviceStatusHandler),

		rest.Put(uriTenantLimit, d.PutTenantLimitHandler),

		rest.Get(uriTenantLimit, d.GetTenantLimitHandler),

		rest.Get(uriLimit, d.GetLimit),

		rest.Post(uriTenants, d.ProvisionTenantHandler),

		rest.Get(uriTenantDeviceStatus, d.GetTenantDeviceStatus),

		rest.Put(uriDevadmAuthSetStatus, d.DevAdmUpdateAuthSetStatusHandler),

		rest.Get(uriDevadmAuthSetStatus, d.DevAdmGetAuthSetStatusHandler),

		rest.Get(uriDevadmDevices, d.DevAdmGetDevicesHandler),

		rest.Post(uriDevadmDevices, d.DevAdmPostDevicesHandler),
		rest.Get(uriDevadmDevice, d.DevAdmGetDeviceHandler),
		rest.Delete(uriDevadmDevice, d.DevAdmDeleteDeviceAuthSetHandler),
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

	err = utils.VerifyAuthReqSign(signature, authreq.PubKey, body)
	if err != nil {
		rest_utils.RestErrWithLogMsg(w, r, l, err, http.StatusUnauthorized, "signature verification failed")
		return
	}

	token, err := d.devAuth.SubmitAuthRequest(ctx, &authreq)

	if err != nil && devauth.IsErrDevAuthUnauthorized(err) {
		rest_utils.RestErrWithWarningMsg(w, r, l, err,
			http.StatusUnauthorized, errors.Cause(err).Error())
		return
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

func (d *DevAuthApiHandlers) PreauthDeviceHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	req, err := model.ParsePreAuthReq(r.Body)
	if err != nil {
		err = errors.Wrap(err, "failed to decode preauth request")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err = d.devAuth.PreauthorizeDevice(ctx, req)
	switch err {
	case nil:
		w.WriteHeader(http.StatusCreated)
	case devauth.ErrDeviceExists:
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusConflict)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
	}
}

func (d *DevAuthApiHandlers) GetDevicesHandler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	page, perPage, err := rest_utils.ParsePagination(r)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	skip := (page - 1) * perPage
	limit := perPage + 1
	devs, err := d.devAuth.GetDevices(ctx, uint(skip), uint(limit))
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
	w.WriteJson(devs[:len])
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

func (d *DevAuthApiHandlers) GetDeviceHandler(w rest.ResponseWriter, r *rest.Request) {

	ctx := r.Context()

	l := log.FromContext(ctx)

	devId := r.PathParam("id")

	dev, err := d.devAuth.GetDevice(ctx, devId)
	switch {
	case err == store.ErrDevNotFound:
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusNotFound)
	case dev != nil:
		w.WriteJson(dev)
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
		if err == store.ErrDevNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthApiHandlers) DevAdmDeleteDeviceAuthSetHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	authId := r.PathParam("aid")

	aset, err := d.db.GetAuthSetById(ctx, authId)
	switch err {
	case nil:
		break
	case store.ErrDevNotFound:
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	err = d.devAuth.DeleteAuthSet(ctx, aset.DeviceId, authId)
	switch err {
	case nil:
		w.WriteHeader(http.StatusNoContent)
	case store.ErrDevNotFound:
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}
}

func (d *DevAuthApiHandlers) DeleteTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()

	l := log.FromContext(ctx)

	tokenId := r.PathParam("id")

	err := d.devAuth.RevokeToken(ctx, tokenId)
	if err != nil {
		if err == store.ErrTokenNotFound {
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

	// TODO backwards compatibility, :id used to be device ID, but now it
	// means authentication set ID

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
		case store.ErrDevNotFound:
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

func (d *DevAuthApiHandlers) GetLimit(w rest.ResponseWriter, r *rest.Request) {
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

func (d *DevAuthApiHandlers) DevAdmUpdateAuthSetStatusHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	authid := r.PathParam("aid")

	var status model.Status
	err := r.DecodeJsonPayload(&status)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l,
			errors.Wrap(err, "failed to decode status data"),
			http.StatusBadRequest)
		return
	}

	// validate status
	if status.Status != model.DevStatusAccepted &&
		status.Status != model.DevStatusRejected {
		rest_utils.RestErrWithLog(w, r, l,
			errors.New("incorrect device status"),
			http.StatusBadRequest)
		return
	}

	// get device id with authset directly from store
	aset, err := d.db.GetAuthSetById(ctx, authid)
	switch err {
	case nil:
		break
	case store.ErrDevNotFound:
		rest_utils.RestErrWithLog(w, r, l, store.ErrAuthSetNotFound, http.StatusNotFound)
		return
	default:
		rest_utils.RestErrWithLogInternal(w, r, l,
			errors.Wrapf(err,
				"failed to fetch auth set %s",
				authid))
		return
	}

	if status.Status == model.DevStatusAccepted {
		err = d.devAuth.AcceptDeviceAuth(ctx, aset.DeviceId, authid)
	} else if status.Status == model.DevStatusRejected {
		err = d.devAuth.RejectDeviceAuth(ctx, aset.DeviceId, authid)
	}

	switch err {
	case nil:
		w.WriteJson(&status)
	case store.ErrDevNotFound:
		rest_utils.RestErrWithLog(w, r, l, store.ErrAuthSetNotFound, http.StatusNotFound)
	case devauth.ErrMaxDeviceCountReached:
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnprocessableEntity)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l,
			errors.Wrap(err,
				"failed to change auth set status"))
	}
}

func (d *DevAuthApiHandlers) DevAdmGetAuthSetStatusHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	authid := r.PathParam("aid")

	// get authset directly from store
	aset, err := d.db.GetAuthSetById(ctx, authid)
	switch err {
	case nil:
		break
	case store.ErrDevNotFound:
		rest_utils.RestErrWithLog(w, r, l, store.ErrAuthSetNotFound, http.StatusNotFound)
		return
	default:
		rest_utils.RestErrWithLogInternal(w, r, l,
			errors.Wrapf(err,
				"failed to fetch auth set %s",
				authid))
		return
	}

	switch err {
	case nil:
		w.WriteJson(&model.Status{Status: aset.Status})
	case store.ErrDevNotFound:
		rest_utils.RestErrWithLog(w, r, l, store.ErrAuthSetNotFound, http.StatusNotFound)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l,
			errors.Wrap(err, "failed to get auth set status"))
	}
}

func (d *DevAuthApiHandlers) DevAdmGetDevicesHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	page, perPage, err := rest_utils.ParsePagination(r)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	status, err := rest_utils.ParseQueryParmStr(r, "status", false, DevStatuses)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	deviceId, err := rest_utils.ParseQueryParmStr(r, "device_id", false, nil)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	//get one extra device to see if there's a 'next' page
	devs, err := d.db.GetAuthSets(ctx,
		int((page-1)*perPage), int(perPage+1),
		store.AuthSetFilter{
			Status:   status,
			DeviceID: deviceId,
		})

	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, errors.Wrap(err, "failed to list devices"))
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

	w.WriteJson(devs[:len])
}

func (d *DevAuthApiHandlers) DevAdmPostDevicesHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	// parse authenticate set
	defer r.Body.Close()
	authSet, err := model.ParseDevAdmAuthSetReq(r.Body)
	if err != nil {
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}
	// translate to devauth object
	req := &model.PreAuthReq{
		DeviceId:  bson.NewObjectId().Hex(),
		AuthSetId: bson.NewObjectId().Hex(),
		IdData:    authSet.DeviceId,
		PubKey:    authSet.Key,
	}

	//TODO: handle identity attributes in one of the tasks of the MEN-1965 epic

	err = d.devAuth.PreauthorizeDevice(ctx, req)
	switch err {
	case nil:
		w.WriteHeader(http.StatusCreated)
	case devauth.ErrDeviceExists:
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusConflict)
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
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

func (d *DevAuthApiHandlers) DevAdmGetDeviceHandler(w rest.ResponseWriter, r *rest.Request) {
	ctx := r.Context()
	l := log.FromContext(ctx)

	authid := r.PathParam("aid")

	auth, err := d.db.GetAuthSetById(ctx, authid)
	switch err {
	case nil:
		break
	case store.ErrDevNotFound:
		rest_utils.RestErrWithLog(w, r, l, store.ErrAuthSetNotFound, http.StatusNotFound)
		return
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	devadm_auth, err := model.NewDevAdmAuthSet(*auth)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteJson(devadm_auth)
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
