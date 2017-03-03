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
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/deviceauth/utils"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/pkg/errors"
)

const (
	uriAuthReqs     = "/api/0.1.0/auth_requests"
	uriDevices      = "/api/0.1.0/devices"
	uriDevice       = "/api/0.1.0/devices/:id"
	uriToken        = "/api/0.1.0/tokens/:id"
	uriTokenVerify  = "/api/0.1.0/tokens/verify"
	uriDeviceStatus = "/api/0.1.0/devices/:id/status"

	HdrAuthReqSign = "X-MEN-Signature"
)

var (
	ErrIncorrectStatus = errors.New("incorrect device status")
	ErrNoAuthHeader    = errors.New("no authorization header")
)

type DevAuthFactory func(l *log.Logger) (DevAuthApp, error)

type DevAuthHandler struct {
	createDevAuth DevAuthFactory
}

type DevAuthApiStatus struct {
	Status string `json:"status"`
}

func NewDevAuthApiHandler(daf DevAuthFactory) ApiHandler {
	return &DevAuthHandler{daf}
}

func (d *DevAuthHandler) GetApp() (rest.App, error) {
	routes := []*rest.Route{
		rest.Post(uriAuthReqs, d.SubmitAuthRequestHandler),

		rest.Get(uriDevices, d.GetDevicesHandler),

		rest.Get(uriDevice, d.GetDeviceHandler),

		rest.Delete(uriToken, d.DeleteTokenHandler),

		rest.Post(uriTokenVerify, d.VerifyTokenHandler),

		rest.Put(uriDeviceStatus, d.UpdateDeviceStatusHandler),
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

func (d *DevAuthHandler) SubmitAuthRequestHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	da, err := d.createDevAuth(l)
	if err != nil {
		restErrWithLogInternal(w, r, l, err)
	}

	var authreq AuthReq

	//validate req body by reading raw content manually
	//(raw body will be needed later, DecodeJsonPayload would
	//unmarshal and close it)
	body, err := utils.ReadBodyRaw(r)
	if err != nil {
		err = errors.Wrap(err, "failed to decode auth request")
		restErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &authreq)
	if err != nil {
		err = errors.Wrap(err, "failed to decode auth request")
		restErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	err = authreq.Validate()
	if err != nil {
		err = errors.Wrap(err, "invalid auth request")
		restErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	//verify signature
	signature := r.Header.Get(HdrAuthReqSign)
	if signature == "" {
		restErrWithLog(w, r, l, errors.New("missing request signature header"), http.StatusBadRequest)
		return
	}

	err = utils.VerifyAuthReqSign(signature, authreq.PubKey, body)
	if err != nil {
		restErrWithLogMsg(w, r, l, err, http.StatusUnauthorized, "signature verification failed")
		return
	}

	ctx := ContextFromRequest(r)
	token, err := da.WithContext(ctx).SubmitAuthRequest(&authreq)
	switch err {
	case ErrDevAuthUnauthorized, ErrDevAuthIdKeyMismatch, ErrDevAuthKeyMismatch:
		// error is always set to unauthorized, client does not need to
		// know why
		restErrWithLogMsg(w, r, l, ErrDevAuthUnauthorized, http.StatusUnauthorized, "unauthorized")
		return
	case nil:
		w.(http.ResponseWriter).Write([]byte(token))
		w.Header().Set("Content-Type", "application/jwt")
		return
	default:
		restErrWithLogInternal(w, r, l, err)
		return
	}
}

func (d *DevAuthHandler) GetDevicesHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	da, err := d.createDevAuth(l)
	if err != nil {
		restErrWithLogInternal(w, r, l, err)
	}

	page, perPage, err := rest_utils.ParsePagination(r)
	if err != nil {
		restErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	skip := (page - 1) * perPage
	limit := perPage + 1
	devs, err := da.GetDevices(uint(skip), uint(limit))
	if err != nil {
		restErrWithLogInternal(w, r, l, err)
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

func (d *DevAuthHandler) GetDeviceHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	da, err := d.createDevAuth(l)
	if err != nil {
		restErrWithLogInternal(w, r, l, err)
	}

	devId := r.PathParam("id")

	dev, err := da.GetDevice(devId)
	switch {
	case err == ErrDevNotFound:
		restErrWithLog(w, r, l, err, http.StatusNotFound)
	case dev != nil:
		w.WriteJson(dev)
	default:
		restErrWithLogInternal(w, r, l, err)
	}
}

func (d *DevAuthHandler) DeleteTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	da, err := d.createDevAuth(l)
	if err != nil {
		restErrWithLogInternal(w, r, l, err)
	}

	tokenId := r.PathParam("id")

	err = da.RevokeToken(tokenId)
	if err != nil {
		if err == ErrTokenNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		restErrWithLogInternal(w, r, l, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthHandler) VerifyTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	da, err := d.createDevAuth(l)
	if err != nil {
		restErrWithLogInternal(w, r, l, err)
	}

	tokenStr, err := extractToken(r.Header)
	if err != nil {
		restErrWithLog(w, r, l, ErrNoAuthHeader, http.StatusUnauthorized)
	}
	// verify token
	err = da.VerifyToken(tokenStr)
	code := http.StatusOK
	if err != nil {
		switch err {
		case ErrTokenExpired:
			code = http.StatusForbidden
		case ErrTokenNotFound, ErrTokenInvalid:
			code = http.StatusUnauthorized
		default:
			restErrWithLogInternal(w, r, l, err)
			return
		}
		l.F(log.Ctx{}).Error(err)
	}

	w.WriteHeader(code)
}

func (d *DevAuthHandler) UpdateDeviceStatusHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	da, err := d.createDevAuth(l)
	if err != nil {
		restErrWithLogInternal(w, r, l, err)
	}

	devid := r.PathParam("id")

	// TODO backwards compatibility, :id used to be device ID, but now it
	// means authentication set ID

	var status DevAuthApiStatus
	err = r.DecodeJsonPayload(&status)
	if err != nil {
		err = errors.Wrap(err, "failed to decode status data")
		restErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	if err = statusValidate(&status); err != nil {
		restErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	if status.Status == DevStatusAccepted {
		ctx := ContextFromRequest(r)
		err = da.WithContext(ctx).AcceptDevice(devid)
	} else if status.Status == DevStatusRejected {
		err = da.RejectDevice(devid)
	} else if status.Status == DevStatusPending {
		err = da.ResetDevice(devid)
	}
	if err != nil {
		if err == ErrDevNotFound {
			restErrWithLog(w, r, l, err, http.StatusNotFound)
		} else {
			restErrWithLogInternal(w, r, l, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// return selected http code + error message directly taken from error
// log error
func restErrWithLog(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int) {
	restErrWithLogMsg(w, r, l, e, code, e.Error())
}

// return http 500, with an "internal error" message
// log full error
func restErrWithLogInternal(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error) {
	msg := "internal error"
	e = errors.Wrap(e, msg)
	restErrWithLogMsg(w, r, l, e, http.StatusInternalServerError, msg)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error
func restErrWithLogMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	w.WriteHeader(code)
	err := w.WriteJson(map[string]string{
		rest.ErrorFieldName: msg,
		"request_id":        requestid.GetReqId(r),
	})
	if err != nil {
		panic(err)
	}
	l.F(log.Ctx{}).Error(errors.Wrap(e, msg).Error())
}

// Validate status.
// Expected statuses:
// - "accepted"
// - "rejected"
// - "pending"
func statusValidate(status *DevAuthApiStatus) error {
	if status.Status != DevStatusAccepted &&
		status.Status != DevStatusRejected &&
		status.Status != DevStatusPending {
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
