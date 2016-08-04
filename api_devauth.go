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
)

var (
	ErrIncorrectStatus = errors.New("incorrect device status")
	ErrNoAuthHeader    = errors.New("no authorization header")
)

type DevAuthHandler struct {
	DevAuth DevAuthApp
}

type DevAuthApiStatus struct {
	Status string `json:"status"`
}

func NewDevAuthApiHandler(devauth DevAuthApp) ApiHandler {
	return &DevAuthHandler{devauth}
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
	var authreq AuthReq

	//validate req body by reading raw content manually
	//(raw body will be needed later, DecodeJsonPayload would
	//unmarshal and close it)
	body, err := utils.ReadBodyRaw(r)
	if err != nil {
		rest.Error(w,
			errors.Wrap(err, "failed to decode auth request").Error(),
			http.StatusBadRequest)
		return
	}

	err = json.Unmarshal(body, &authreq)
	if err != nil {
		rest.Error(w,
			errors.Wrap(err, "failed to decode auth request").Error(),
			http.StatusBadRequest)
		return
	}

	err = authreq.Validate()
	if err != nil {
		rest.Error(w,
			errors.Wrap(err, "invalid auth request").Error(),
			http.StatusBadRequest)
		return
	}

	//verify signature
	signature := r.Header.Get(HdrAuthReqSign)
	if signature == "" {
		rest.Error(w,
			"missing request signature header",
			http.StatusBadRequest)
		return
	}

	err = utils.VerifyAuthReqSign(signature, authreq.PubKey, body)
	if err != nil {
		rest.Error(w,
			"signature verification failed",
			http.StatusUnauthorized)
		return
	}

	ctx := ContextFromRequest(r)
	token, err := d.DevAuth.WithContext(ctx).SubmitAuthRequest(&authreq)
	switch err {
	case ErrDevAuthUnauthorized:
		rest.Error(w,
			"unauthorized",
			http.StatusUnauthorized)
		return
	case nil:
		w.(http.ResponseWriter).Write([]byte(token))
		return
	default:
		rest.Error(w,
			"internal error",
			http.StatusInternalServerError)
		return
	}

}

func (d *DevAuthHandler) GetAuthRequestsHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDevicesHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDeviceHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) UpdateDeviceHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDeviceTokenHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) DeleteTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	tokenId := r.PathParam("id")
	err := d.DevAuth.RevokeToken(tokenId)
	if err != nil {
		if err == ErrTokenNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rest.Error(w, ErrDevAuthInternal.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *DevAuthHandler) VerifyTokenHandler(w rest.ResponseWriter, r *rest.Request) {
	tokenStr, err := extractToken(r.Header)
	if err != nil {
		rest.Error(w, ErrNoAuthHeader.Error(), http.StatusUnauthorized)
	}
	// verify token
	err = d.DevAuth.VerifyToken(tokenStr)
	switch err {
	case nil:
		w.WriteHeader(http.StatusOK)
	case ErrTokenExpired:
		w.WriteHeader(http.StatusForbidden)
	case ErrTokenNotFound, ErrTokenInvalid:
		w.WriteHeader(http.StatusUnauthorized)
	default:
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (d *DevAuthHandler) UpdateDeviceStatusHandler(w rest.ResponseWriter, r *rest.Request) {
	devid := r.PathParam("id")

	var status DevAuthApiStatus
	err := r.DecodeJsonPayload(&status)
	if err != nil {
		rest.Error(w,
			errors.Wrap(err, "failed to decode status data").Error(),
			http.StatusBadRequest)
		return
	}

	if err = statusValidate(&status); err != nil {
		rest.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if status.Status == DevStatusAccepted {
		err = d.DevAuth.AcceptDevice(devid)
	} else if status.Status == DevStatusRejected {
		err = d.DevAuth.RejectDevice(devid)
	}
	if err != nil {
		code := http.StatusInternalServerError
		if err == ErrDevNotFound {
			code = http.StatusNotFound
		}
		rest.Error(w, err.Error(), code)
		return
	}

	devurl := utils.BuildURL(r, uriDevice, map[string]string{
		":id": devid,
	})
	w.Header().Add("Location", devurl.String())
	w.WriteHeader(http.StatusSeeOther)
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
