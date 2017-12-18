// Copyright 2017 Northern.tech AS
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

package store

import (
	"context"
	"errors"

	"github.com/mendersoftware/deviceauth/model"
)

var (
	// device not found
	ErrDevNotFound = errors.New("device not found")
	// token not found
	ErrTokenNotFound = errors.New("token not found")
	// authorization set not found
	ErrAuthSetNotFound = errors.New("authorization set not found")
	// limit  set not found
	ErrLimitNotFound = errors.New("limit not found")
	// device already exists
	ErrObjectExists = errors.New("object exists")
)

type DataStore interface {
	// retrieve device by Mender-assigned device ID
	//returns ErrDevNotFound if device not found
	GetDeviceById(ctx context.Context, id string) (*model.Device, error)

	// retrieve device by its identity data
	// returns ErrDevNotFound if device not found
	GetDeviceByIdentityData(ctx context.Context, idata string) (*model.Device, error)

	// list devices
	GetDevices(ctx context.Context, skip, limit uint) ([]model.Device, error)

	AddDevice(ctx context.Context, d model.Device) error

	// updates a single device with ID `d.Id`, using data from `up`
	UpdateDevice(ctx context.Context, d model.Device, up model.DeviceUpdate) error

	// deletes device
	DeleteDevice(ctx context.Context, id string) error

	AddAuthSet(ctx context.Context, set model.AuthSet) error

	GetAuthSetByDataKey(ctx context.Context, data string, key string) (*model.AuthSet, error)

	GetAuthSetById(ctx context.Context, id string) (*model.AuthSet, error)

	GetAuthSetsForDevice(ctx context.Context, devid string) ([]model.AuthSet, error)

	// update matching AuthSets and set their fields to values in AuthSetUpdate
	UpdateAuthSet(ctx context.Context, filter interface{}, mod model.AuthSetUpdate) error

	// deletes all auth sets for device
	DeleteAuthSetsForDevice(ctx context.Context, devid string) error

	// adds JWT to database
	AddToken(ctx context.Context, t model.Token) error

	// retrieves JWT from database using JWT Id and device Id
	// returns ErrTokenNotFound if token not found
	GetToken(ctx context.Context, jti string) (*model.Token, error)

	// deletes token
	DeleteToken(ctx context.Context, jti string) error

	// deletes device token
	DeleteTokenByDevId(ctx context.Context, dev_id string) error

	// put limit information into data store
	PutLimit(ctx context.Context, lim model.Limit) error

	// fetch limit information from data store
	GetLimit(ctx context.Context, name string) (*model.Limit, error)

	// get the number of devices with a given admission status
	// computed based on aggregated auth set statuses
	GetDevCountByStatus(ctx context.Context, status string) (int, error)

	MigrateTenant(ctx context.Context, version string, tenant string) error
	WithAutomigrate() DataStore
}
