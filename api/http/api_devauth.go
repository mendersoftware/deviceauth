// Copyright 2017 Northern.tech AS
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

	uriDevices      = "/api/management/v1/devauth/devices"
	uriDevicesCount = "/api/management/v1/devauth/devices/count"
	uriDevice       = "/api/management/v1/devauth/devices/:id"
	uriToken        = "/api/management/v1/devauth/tokens/:id"
	uriDeviceStatus = "/api/management/v1/devauth/devices/:id/auth/:aid/status"
	uriLimit        = "/api/management/v1/devauth/limits/:name"

	// internal API
	uriTokenVerify = "/api/internal/v1/devauth/tokens/verify"
	uriTenantLimit = "/api/internal/v1/devauth/tenant/:id/limits/:name"

	HdrAuthReqSign = "X-MEN-Signature"
)

var (
	ErrIncorrectStatus = errors.New("incorrect device status")
	ErrNoAuthHeader    = errors.New("no authorization header")
)

type DevAuthApiHandlers struct {
	devAuth devauth.App
}

type DevAuthApiStatus struct {
	Status string `json:"status"`
}

func NewDevAuthApiHandlers(devAuth devauth.App) ApiHandler {
	return &DevAuthApiHandlers{
		devAuth: devAuth,
	}
}

func (d *DevAuthApiHandlers) GetApp() (rest.App, error) {
	routes := []*rest.Route{
		rest.Post(uriAuthReqs, d.SubmitAuthRequestHandler),

		rest.Get(uriDevices, d.GetDevicesHandler),

		rest.Get(uriDevicesCount, d.GetDevicesCountHandler),

		rest.Get(uriDevice, d.GetDeviceHandler),

		rest.Delete(uriDevice, d.DeleteDeviceHandler),

		rest.Delete(uriToken, d.DeleteTokenHandler),

		rest.Post(uriTokenVerify, d.VerifyTokenHandler),

		rest.Put(uriDeviceStatus, d.UpdateDeviceStatusHandler),

		rest.Put(uriTenantLimit, d.PutTenantLimitHandler),

		rest.Get(uriTenantLimit, d.GetTenantLimitHandler),

		rest.Get(uriLimit, d.GetLimit),
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
	switch err {
	case devauth.ErrDevAuthUnauthorized, devauth.ErrDevIdAuthIdMismatch:
		// error is always set to unauthorized, client does not need to
		// know why
		rest_utils.RestErrWithLogMsg(w, r, l, devauth.ErrDevAuthUnauthorized,
			http.StatusUnauthorized, "unauthorized")
		return
	case nil:
		ww := w.(http.ResponseWriter)
		ww.Header().Set("Content-Type", "application/jwt")
		ww.Write([]byte(token))
		return
	default:
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
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
		"":
	default:
		rest_utils.RestErrWithLog(w, r, l, errors.New("status must be one of: pending, accepted, rejected"), http.StatusBadRequest)
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
