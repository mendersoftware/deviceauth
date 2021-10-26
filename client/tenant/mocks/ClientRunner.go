// Copyright 2021 Northern.tech AS
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

// Code generated by mockery v2.3.0. DO NOT EDIT.

package mocks

import (
	context "context"

	tenant "github.com/mendersoftware/deviceauth/client/tenant"
	mock "github.com/stretchr/testify/mock"
)

// ClientRunner is an autogenerated mock type for the ClientRunner type
type ClientRunner struct {
	mock.Mock
}

// CheckHealth provides a mock function with given fields: ctx
func (_m *ClientRunner) CheckHealth(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetTenant provides a mock function with given fields: ctx, tid
func (_m *ClientRunner) GetTenant(ctx context.Context, tid string) (*tenant.Tenant, error) {
	ret := _m.Called(ctx, tid)

	var r0 *tenant.Tenant
	if rf, ok := ret.Get(0).(func(context.Context, string) *tenant.Tenant); ok {
		r0 = rf(ctx, tid)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*tenant.Tenant)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, tid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetTenantUsers provides a mock function with given fields: ctx, tenantID
func (_m *ClientRunner) GetTenantUsers(ctx context.Context, tenantID string) ([]tenant.User, error) {
	ret := _m.Called(ctx, tenantID)

	var r0 []tenant.User
	if rf, ok := ret.Get(0).(func(context.Context, string) []tenant.User); ok {
		r0 = rf(ctx, tenantID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]tenant.User)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, tenantID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// VerifyToken provides a mock function with given fields: ctx, token
func (_m *ClientRunner) VerifyToken(ctx context.Context, token string) (*tenant.Tenant, error) {
	ret := _m.Called(ctx, token)

	var r0 *tenant.Tenant
	if rf, ok := ret.Get(0).(func(context.Context, string) *tenant.Tenant); ok {
		r0 = rf(ctx, token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*tenant.Tenant)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
