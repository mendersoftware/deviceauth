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

	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/deviceauth/requestid"
)

type MockDevAuth struct {
	mockSubmitAuthRequest           func(r *AuthReq) (string, error)
	mockSubmitAuthRequestWithClient func(r *AuthReq, c requestid.ApiRequester) (string, error)
	mockAcceptDevice                func(dev_id string) error
	mockRejectDevice                func(dev_id string) error
	mockResetDevice                 func(dev_id string) error
	mockVerifyToken                 func(token string) error
	mockRevokeToken                 func(tokenId string) error
	mockWithContext                 func(ctx *RequestContext) DevAuthApp
	mockGetDevices                  func(skip, limit uint) ([]Device, error)
}

func (mda *MockDevAuth) SubmitAuthRequest(r *AuthReq) (string, error) {
	return mda.mockSubmitAuthRequest(r)
}

func (mda *MockDevAuth) SubmitAuthRequestWithClient(r *AuthReq, c requestid.ApiRequester) (string, error) {
	return mda.mockSubmitAuthRequestWithClient(r, c)
}

func (mda *MockDevAuth) GetDevices(skip, limit uint) ([]Device, error) {
	return mda.mockGetDevices(skip, limit)
}

func (mda *MockDevAuth) GetDevice(dev_id string) (*Device, error) {
	return nil, errors.New("not implemented")
}

func (mda *MockDevAuth) AcceptDevice(dev_id string) error {
	return mda.mockAcceptDevice(dev_id)
}

func (mda *MockDevAuth) RejectDevice(dev_id string) error {
	return mda.mockRejectDevice(dev_id)
}

func (mda *MockDevAuth) ResetDevice(dev_id string) error {
	return mda.mockResetDevice(dev_id)
}

func (mda *MockDevAuth) GetDeviceToken(dev_id string) (*Token, error) {
	return nil, errors.New("not implemented")
}

func (mda *MockDevAuth) RevokeToken(tokenId string) error {
	return mda.mockRevokeToken(tokenId)
}

func (mda *MockDevAuth) VerifyToken(token string) error {
	return mda.mockVerifyToken(token)
}
func (mda *MockDevAuth) WithContext(ctx *RequestContext) DevAuthApp {
	return mda.mockWithContext(ctx)
}

func (mda *MockDevAuth) UseLog(log *log.Logger) {
	//nop
}
