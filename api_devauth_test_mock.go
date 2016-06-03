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
	"errors"
)

type MockDevAuth struct {
	mockSubmitAuthRequest func(r *AuthReq) (string, error)
}

func (mda *MockDevAuth) SubmitAuthRequest(r *AuthReq) (string, error) {
	return mda.mockSubmitAuthRequest(r)
}
func (mda *MockDevAuth) GetAuthRequests(dev_id string) ([]AuthReq, error) {
	return nil, errors.New("not implemented")
}

func (mda *MockDevAuth) GetDevices(skip, limit int, tenant_token, status string) ([]Device, error) {
	return nil, errors.New("not implemented")
}

func (mda *MockDevAuth) GetDevice(dev_id string) (*Device, error) {
	return nil, errors.New("not implemented")
}

func (mda *MockDevAuth) AcceptDevice(dev_id string) error {
	return errors.New("not implemented")
}

func (mda *MockDevAuth) RejectDevice(dev_id string) error {
	return errors.New("not implemented")
}

func (mda *MockDevAuth) GetDeviceToken(dev_id string) (*Token, error) {
	return nil, errors.New("not implemented")
}

func (mda *MockDevAuth) RevokeToken(token_id string) error {
	return errors.New("not implemented")
}

func (mda *MockDevAuth) VerifyToken(token string) (bool, error) {
	return false, errors.New("not implemented")
}
