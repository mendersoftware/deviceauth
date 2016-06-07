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
)

const (
	uriAuthReqs    = "/api/0.1.0/auth_requests"
	uriDevices     = "/api/0.1.0/devices"
	uriDevice      = "/api/0.1.0/devices/:id"
	uriDeviceToken = "/api/0.1.0/devices/:id/token"
	uriToken       = "/api/0.1.0/tokens/:id"
	uriTokenVerify = "/api/0.1.0/tokens/verify"

	HdrAuthReqSign = "X-MEN-Signature"
)

type DevAuthHandler struct {
	DevAuth DevAuthApp
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

		rest.Put(uriToken, d.UpdateTokenHandler),

		rest.Post(uriTokenVerify, d.VerifyTokenHandler),
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

	token, err := d.DevAuth.SubmitAuthRequest(&authreq)
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

func (d *DevAuthHandler) UpdateTokenHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) VerifyTokenHandler(w rest.ResponseWriter, r *rest.Request) {}
