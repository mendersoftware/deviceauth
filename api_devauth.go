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
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/deviceauth/config"
	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/deviceauth/requestid"
	"github.com/mendersoftware/deviceauth/utils"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

const (
	uriAuthReqs     = "/api/0.1.0/auth_requests"
	uriDevices      = "/api/0.1.0/devices"
	uriDevice       = "/api/0.1.0/devices/:id"
	uriDeviceToken  = "/api/0.1.0/devices/:id/token"
	uriToken        = "/api/0.1.0/tokens/:id"
	uriTokenVerify  = "/api/0.1.0/tokens/verify"
	uriDeviceStatus = "/api/0.1.0/devices/:id/status"

	HdrAuthReqSign = "X-MEN-Signature"

	LogReqId    = "request_id"
	LogApiCall  = "api_call"
	LogHttpCode = "http_code"
)

var (
	ErrIncorrectStatus = errors.New("incorrect device status")
	ErrNoAuthHeader    = errors.New("no authorization header")
)

type DevAuthFactory func(c config.Reader, l *log.Logger) (DevAuthApp, error)

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
		rest.Get(uriAuthReqs, d.GetAuthRequestsHandler),

		rest.Get(uriDevices, d.GetDevicesHandler),

		rest.Get(uriDevice, d.GetDeviceHandler),
		rest.Put(uriDevice, d.UpdateDeviceHandler),

		rest.Get(uriDeviceToken, d.GetDeviceTokenHandler),

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
	l := log.New(log.Ctx{
		LogReqId:   requestid.GetReqId(r),
		LogApiCall: "SubmitAuthRequestHandler"})

	da, err := d.createDevAuth(config.Config, l)
	if err != nil {
		restErrWithLogInternal(w, l, err)
	}

	var authreq AuthReq

	//validate req body by reading raw content manually
	//(raw body will be needed later, DecodeJsonPayload would
	//unmarshal and close it)
	body, err := utils.ReadBodyRaw(r)
	if err != nil {
		err = errors.Wrap(err, "failed to decode auth request")
		restErrWithLog(w, l, err, http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &authreq)
	if err != nil {
		err = errors.Wrap(err, "failed to decode auth request")
		restErrWithLog(w, l, err, http.StatusBadRequest)
		return
	}

	err = authreq.Validate()
	if err != nil {
		err = errors.Wrap(err, "invalid auth request")
		restErrWithLog(w, l, err, http.StatusBadRequest)
		return
	}

	//verify signature
	signature := r.Header.Get(HdrAuthReqSign)
	if signature == "" {
		restErrWithLog(w, l, errors.New("missing request signature header"), http.StatusBadRequest)
		return
	}

	err = utils.VerifyAuthReqSign(signature, authreq.PubKey, body)
	if err != nil {
		restErrWithLogMsg(w, l, err, http.StatusUnauthorized, "signature verification failed")
		return
	}

	ctx := ContextFromRequest(r)
	token, err := da.WithContext(ctx).SubmitAuthRequest(&authreq)
	switch err {
	case ErrDevAuthUnauthorized:
		restErrWithLogMsg(w, l, err, http.StatusUnauthorized, "unauthorized")
		return
	case nil:
		l.F(log.Ctx{LogHttpCode: http.StatusOK}).
			Info("ok")
		w.(http.ResponseWriter).Write([]byte(token))
		return
	default:
		restErrWithLogInternal(w, l, err)
		return
	}
}

func (d *DevAuthHandler) GetAuthRequestsHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDevicesHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDeviceHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) UpdateDeviceHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDeviceTokenHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) DeleteTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	l := log.New(log.Ctx{
		LogReqId:   requestid.GetReqId(r),
		LogApiCall: "DeleteTokenHandler"})

	da, err := d.createDevAuth(config.Config, l)
	if err != nil {
		restErrWithLogInternal(w, l, err)
	}

	tokenId := r.PathParam("id")

	err = da.RevokeToken(tokenId)
	if err != nil {
		if err == ErrTokenNotFound {
			l.F(log.Ctx{LogHttpCode: http.StatusNotFound}).
				Error(err.Error())
			w.WriteHeader(http.StatusNotFound)
			return
		}
		restErrWithLogInternal(w, l, err)
		return
	}

	l.F(log.Ctx{LogHttpCode: http.StatusNoContent}).
		Info("ok")
	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthHandler) VerifyTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	l := log.New(log.Ctx{
		LogReqId:   requestid.GetReqId(r),
		LogApiCall: "VerifyTokenHandler"})

	da, err := d.createDevAuth(config.Config, l)
	if err != nil {
		restErrWithLogInternal(w, l, err)
	}

	tokenStr, err := extractToken(r.Header)
	if err != nil {
		restErrWithLog(w, l, ErrNoAuthHeader, http.StatusUnauthorized)
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
			code = http.StatusInternalServerError
			rest.Error(w, "internal error", code)
		}

		l.F(log.Ctx{LogHttpCode: code}).
			Error(err.Error())
	} else {
		l.F(log.Ctx{LogHttpCode: code}).
			Info("ok")
	}

	w.WriteHeader(code)
}

func (d *DevAuthHandler) UpdateDeviceStatusHandler(w rest.ResponseWriter, r *rest.Request) {
	l := log.New(log.Ctx{
		LogReqId:   requestid.GetReqId(r),
		LogApiCall: "UpdateDeviceStatusHandler"})

	da, err := d.createDevAuth(config.Config, l)
	if err != nil {
		restErrWithLogInternal(w, l, err)
	}

	devid := r.PathParam("id")

	var status DevAuthApiStatus
	err = r.DecodeJsonPayload(&status)
	if err != nil {
		err = errors.Wrap(err, "failed to decode status data")
		restErrWithLog(w, l, err, http.StatusBadRequest)
		return
	}

	if err = statusValidate(&status); err != nil {
		restErrWithLog(w, l, err, http.StatusBadRequest)
		return
	}

	if status.Status == DevStatusAccepted {
		err = da.AcceptDevice(devid)
	} else if status.Status == DevStatusRejected {
		err = da.RejectDevice(devid)
	}
	if err != nil {
		if err == ErrDevNotFound {
			restErrWithLog(w, l, err, http.StatusNotFound)
		} else {
			restErrWithLogInternal(w, l, err)
		}
		return
	}

	devurl := utils.BuildURL(r, uriDevice, map[string]string{
		":id": devid,
	})

	l.F(log.Ctx{LogHttpCode: http.StatusSeeOther}).
		Info("ok")
	w.Header().Add("Location", devurl.String())
	w.WriteHeader(http.StatusSeeOther)
}

// return selected http code + error message directly taken from error
// log error
func restErrWithLog(w rest.ResponseWriter, l *log.Logger, e error, code int) {
	restErrWithLogMsg(w, l, e, code, e.Error())
}

// return http 500, with an "internal error" message
// log full error
func restErrWithLogInternal(w rest.ResponseWriter, l *log.Logger, e error) {
	msg := "internal error"
	e = errors.Wrap(e, msg)
	restErrWithLogMsg(w, l, e, http.StatusInternalServerError, msg)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error
func restErrWithLogMsg(w rest.ResponseWriter, l *log.Logger, e error, code int, msg string) {
	rest.Error(w, msg, code)
	l.F(log.Ctx{LogHttpCode: code}).Error(errors.Wrap(e, msg).Error())
}

// Validate status.
// Expected statuses:
// - "accepted"
// - "rejected"
func statusValidate(status *DevAuthApiStatus) error {
	if status.Status != DevStatusAccepted &&
		status.Status != DevStatusRejected {
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
