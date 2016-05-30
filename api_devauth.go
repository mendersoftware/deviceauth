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
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/pkg/errors"
)

const (
	uriAuthReqs    = "/api/0.1.0/auth_requests"
	uriDevices     = "/api/0.1.0/devices"
	uriDevice      = "/api/0.1.0/devices/:id"
	uriDeviceToken = "/api/0.1.0/devices/:id/token"
	uriToken       = "/api/0.1.0/tokens/:id"
	uriTokenVerify = "/api/0.1.0/tokens/verify"
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

func (d *DevAuthHandler) SubmitAuthRequestHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetAuthRequestsHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDevicesHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDeviceHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) UpdateDeviceHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) GetDeviceTokenHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) UpdateTokenHandler(w rest.ResponseWriter, r *rest.Request) {}

func (d *DevAuthHandler) VerifyTokenHandler(w rest.ResponseWriter, r *rest.Request) {}
