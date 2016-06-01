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
	"github.com/pkg/errors"
)

// this device auth service interface
type DevAuthApp interface {
	SubmitAuthRequest(r *AuthReq) error
	GetAuthRequests(dev_id string) ([]AuthReq, error)

	GetDevices(skip, limit int, tenant_token, status string) ([]Device, error)
	GetDevice(dev_id string) (*Device, error)
	AcceptDevice(dev_id string) error
	RejectDevice(dev_id string) error
	GetDeviceToken(dev_id string) (*Token, error)

	RevokeToken(token_id string) error
	VerifyToken(token string) (bool, error)
}

type DevAuth struct {
}

func NewDevAuth() DevAuthApp {
	return &DevAuth{}
}

func (*DevAuth) SubmitAuthRequest(r *AuthReq) error {
	return errors.New("not implemented")
}
func (*DevAuth) GetAuthRequests(dev_id string) ([]AuthReq, error) {
	return nil, errors.New("not implemented")
}

func (*DevAuth) GetDevices(skip, limit int, tenant_token, status string) ([]Device, error) {
	return nil, errors.New("not implemented")
}

func (*DevAuth) GetDevice(dev_id string) (*Device, error) {
	return nil, errors.New("not implemented")
}

func (*DevAuth) AcceptDevice(dev_id string) error {
	return errors.New("not implemented")
}

func (*DevAuth) RejectDevice(dev_id string) error {
	return errors.New("not implemented")
}

func (*DevAuth) GetDeviceToken(dev_id string) (*Token, error) {
	return nil, errors.New("not implemented")
}

func (*DevAuth) RevokeToken(token_id string) error {
	return errors.New("not implemented")
}

func (*DevAuth) VerifyToken(token string) (bool, error) {
	return false, errors.New("not implemented")
}
