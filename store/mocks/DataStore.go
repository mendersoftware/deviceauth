// Copyright 2023 Northern.tech AS
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

	jwt "github.com/mendersoftware/deviceauth/jwt"
	migrate "github.com/mendersoftware/go-lib-micro/mongo/migrate"

	mock "github.com/stretchr/testify/mock"

	model "github.com/mendersoftware/deviceauth/model"

	oid "github.com/mendersoftware/go-lib-micro/mongo/oid"

	store "github.com/mendersoftware/deviceauth/store"
)

// DataStore is an autogenerated mock type for the DataStore type
type DataStore struct {
	mock.Mock
}

// AddAuthSet provides a mock function with given fields: ctx, set
func (_m *DataStore) AddAuthSet(ctx context.Context, set model.AuthSet) error {
	ret := _m.Called(ctx, set)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, model.AuthSet) error); ok {
		r0 = rf(ctx, set)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddDevice provides a mock function with given fields: ctx, d
func (_m *DataStore) AddDevice(ctx context.Context, d model.Device) error {
	ret := _m.Called(ctx, d)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, model.Device) error); ok {
		r0 = rf(ctx, d)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AddToken provides a mock function with given fields: ctx, t
func (_m *DataStore) AddToken(ctx context.Context, t *jwt.Token) error {
	ret := _m.Called(ctx, t)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *jwt.Token) error); ok {
		r0 = rf(ctx, t)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAuthSetForDevice provides a mock function with given fields: ctx, devId, authId
func (_m *DataStore) DeleteAuthSetForDevice(ctx context.Context, devId string, authId string) error {
	ret := _m.Called(ctx, devId, authId)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, devId, authId)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAuthSetsForDevice provides a mock function with given fields: ctx, devid
func (_m *DataStore) DeleteAuthSetsForDevice(ctx context.Context, devid string) error {
	ret := _m.Called(ctx, devid)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, devid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteDevice provides a mock function with given fields: ctx, id
func (_m *DataStore) DeleteDevice(ctx context.Context, id string) error {
	ret := _m.Called(ctx, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteLimit provides a mock function with given fields: ctx, lim
func (_m *DataStore) DeleteLimit(ctx context.Context, lim string) error {
	ret := _m.Called(ctx, lim)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, lim)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteToken provides a mock function with given fields: ctx, jti
func (_m *DataStore) DeleteToken(ctx context.Context, jti oid.ObjectID) error {
	ret := _m.Called(ctx, jti)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, oid.ObjectID) error); ok {
		r0 = rf(ctx, jti)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteTokenByDevId provides a mock function with given fields: ctx, dev_id
func (_m *DataStore) DeleteTokenByDevId(ctx context.Context, dev_id oid.ObjectID) error {
	ret := _m.Called(ctx, dev_id)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, oid.ObjectID) error); ok {
		r0 = rf(ctx, dev_id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteTokens provides a mock function with given fields: ctx
func (_m *DataStore) DeleteTokens(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ForEachTenant provides a mock function with given fields: parentCtx, opFunc
func (_m *DataStore) ForEachTenant(parentCtx context.Context, opFunc store.MapFunc) error {
	ret := _m.Called(parentCtx, opFunc)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, store.MapFunc) error); ok {
		r0 = rf(parentCtx, opFunc)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetAuthSetById provides a mock function with given fields: ctx, id
func (_m *DataStore) GetAuthSetById(ctx context.Context, id string) (*model.AuthSet, error) {
	ret := _m.Called(ctx, id)

	var r0 *model.AuthSet
	if rf, ok := ret.Get(0).(func(context.Context, string) *model.AuthSet); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.AuthSet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAuthSetByIdDataHashKey provides a mock function with given fields: ctx, idDataHash, key
func (_m *DataStore) GetAuthSetByIdDataHashKey(ctx context.Context, idDataHash []byte, key string) (*model.AuthSet, error) {
	ret := _m.Called(ctx, idDataHash, key)

	var r0 *model.AuthSet
	if rf, ok := ret.Get(0).(func(context.Context, []byte, string) *model.AuthSet); ok {
		r0 = rf(ctx, idDataHash, key)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.AuthSet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, []byte, string) error); ok {
		r1 = rf(ctx, idDataHash, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAuthSetByIdDataHashKeyByStatus provides a mock function with given fields: ctx, idDataHash, key, status
func (_m *DataStore) GetAuthSetByIdDataHashKeyByStatus(ctx context.Context, idDataHash []byte, key string, status string) (*model.AuthSet, error) {
	ret := _m.Called(ctx, idDataHash, key, status)

	var r0 *model.AuthSet
	if rf, ok := ret.Get(0).(func(context.Context, []byte, string, string) *model.AuthSet); ok {
		r0 = rf(ctx, idDataHash, key, status)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.AuthSet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, []byte, string, string) error); ok {
		r1 = rf(ctx, idDataHash, key, status)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetAuthSetsForDevice provides a mock function with given fields: ctx, devid
func (_m *DataStore) GetAuthSetsForDevice(ctx context.Context, devid string) ([]model.AuthSet, error) {
	ret := _m.Called(ctx, devid)

	var r0 []model.AuthSet
	if rf, ok := ret.Get(0).(func(context.Context, string) []model.AuthSet); ok {
		r0 = rf(ctx, devid)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AuthSet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, devid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDevCountByStatus provides a mock function with given fields: ctx, status
func (_m *DataStore) GetDevCountByStatus(ctx context.Context, status string) (int, error) {
	ret := _m.Called(ctx, status)

	var r0 int
	if rf, ok := ret.Get(0).(func(context.Context, string) int); ok {
		r0 = rf(ctx, status)
	} else {
		r0 = ret.Get(0).(int)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, status)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDeviceById provides a mock function with given fields: ctx, id
func (_m *DataStore) GetDeviceById(ctx context.Context, id string) (*model.Device, error) {
	ret := _m.Called(ctx, id)

	var r0 *model.Device
	if rf, ok := ret.Get(0).(func(context.Context, string) *model.Device); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Device)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDeviceByIdentityDataHash provides a mock function with given fields: ctx, idataHash
func (_m *DataStore) GetDeviceByIdentityDataHash(ctx context.Context, idataHash []byte) (*model.Device, error) {
	ret := _m.Called(ctx, idataHash)

	var r0 *model.Device
	if rf, ok := ret.Get(0).(func(context.Context, []byte) *model.Device); ok {
		r0 = rf(ctx, idataHash)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Device)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, []byte) error); ok {
		r1 = rf(ctx, idataHash)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDeviceStatus provides a mock function with given fields: ctx, dev_id
func (_m *DataStore) GetDeviceStatus(ctx context.Context, dev_id string) (string, error) {
	ret := _m.Called(ctx, dev_id)

	var r0 string
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, dev_id)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, dev_id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetDevices provides a mock function with given fields: ctx, skip, limit, filter
func (_m *DataStore) GetDevices(ctx context.Context, skip uint, limit uint, filter model.DeviceFilter) ([]model.Device, error) {
	ret := _m.Called(ctx, skip, limit, filter)

	var r0 []model.Device
	if rf, ok := ret.Get(0).(func(context.Context, uint, uint, model.DeviceFilter) []model.Device); ok {
		r0 = rf(ctx, skip, limit, filter)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Device)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, uint, uint, model.DeviceFilter) error); ok {
		r1 = rf(ctx, skip, limit, filter)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetLimit provides a mock function with given fields: ctx, name
func (_m *DataStore) GetLimit(ctx context.Context, name string) (*model.Limit, error) {
	ret := _m.Called(ctx, name)

	var r0 *model.Limit
	if rf, ok := ret.Get(0).(func(context.Context, string) *model.Limit); ok {
		r0 = rf(ctx, name)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Limit)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetToken provides a mock function with given fields: ctx, jti
func (_m *DataStore) GetToken(ctx context.Context, jti oid.ObjectID) (*jwt.Token, error) {
	ret := _m.Called(ctx, jti)

	var r0 *jwt.Token
	if rf, ok := ret.Get(0).(func(context.Context, oid.ObjectID) *jwt.Token); ok {
		r0 = rf(ctx, jti)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*jwt.Token)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, oid.ObjectID) error); ok {
		r1 = rf(ctx, jti)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListTenantsIds provides a mock function with given fields: ctx
func (_m *DataStore) ListTenantsIds(ctx context.Context) ([]string, error) {
	ret := _m.Called(ctx)

	var r0 []string
	if rf, ok := ret.Get(0).(func(context.Context) []string); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MigrateTenant provides a mock function with given fields: ctx, version, tenant
func (_m *DataStore) MigrateTenant(ctx context.Context, version string, tenant string) error {
	ret := _m.Called(ctx, version, tenant)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, version, tenant)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Ping provides a mock function with given fields: ctx
func (_m *DataStore) Ping(ctx context.Context) error {
	ret := _m.Called(ctx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(ctx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// PutLimit provides a mock function with given fields: ctx, lim
func (_m *DataStore) PutLimit(ctx context.Context, lim model.Limit) error {
	ret := _m.Called(ctx, lim)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, model.Limit) error); ok {
		r0 = rf(ctx, lim)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RejectAuthSetsForDevice provides a mock function with given fields: ctx, deviceID
func (_m *DataStore) RejectAuthSetsForDevice(ctx context.Context, deviceID string) error {
	ret := _m.Called(ctx, deviceID)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string) error); ok {
		r0 = rf(ctx, deviceID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// StoreMigrationVersion provides a mock function with given fields: ctx, version
func (_m *DataStore) StoreMigrationVersion(ctx context.Context, version *migrate.Version) error {
	ret := _m.Called(ctx, version)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *migrate.Version) error); ok {
		r0 = rf(ctx, version)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAuthSetById provides a mock function with given fields: ctx, authId, mod
func (_m *DataStore) UpdateAuthSetById(ctx context.Context, authId string, mod model.AuthSetUpdate) error {
	ret := _m.Called(ctx, authId, mod)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, model.AuthSetUpdate) error); ok {
		r0 = rf(ctx, authId, mod)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateDevice provides a mock function with given fields: ctx, deviceID, up
func (_m *DataStore) UpdateDevice(ctx context.Context, deviceID string, up model.DeviceUpdate) error {
	ret := _m.Called(ctx, deviceID, up)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, model.DeviceUpdate) error); ok {
		r0 = rf(ctx, deviceID, up)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// WithAutomigrate provides a mock function with given fields:
func (_m *DataStore) WithAutomigrate() store.DataStore {
	ret := _m.Called()

	var r0 store.DataStore
	if rf, ok := ret.Get(0).(func() store.DataStore); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(store.DataStore)
		}
	}

	return r0
}
