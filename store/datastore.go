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

package store

import (
	"errors"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/go-lib-micro/log"
)

var (
	// device not found
	ErrDevNotFound = errors.New("device not found")
	// token not found
	ErrTokenNotFound = errors.New("token not found")
	// authorization set not found
	ErrAuthSetNotFound = errors.New("authorization set not found")
	// device already exists
	ErrObjectExists = errors.New("object exists")
)

type DataStore interface {
	// retrieve device by Mender-assigned device ID
	//returns ErrDevNotFound if device not found
	GetDeviceById(id string) (*model.Device, error)

	// retrieve device by its identity data
	// returns ErrDevNotFound if device not found
	GetDeviceByIdentityData(idata string) (*model.Device, error)

	// list devices
	GetDevices(skip, limit uint) ([]model.Device, error)

	AddDevice(d model.Device) error

	// updates a single device selected via d.Id
	// updates only set fields
	UpdateDevice(d *model.Device) error

	// deletes device
	DeleteDevice(id string) error

	AddAuthSet(set model.AuthSet) error

	GetAuthSetByDataKey(data string, key string) (*model.AuthSet, error)

	GetAuthSetById(id string) (*model.AuthSet, error)

	GetAuthSetsForDevice(devid string) ([]model.AuthSet, error)

	// update AuthSet and set its values to ones in AuthSetUpdate
	UpdateAuthSet(orig model.AuthSet, mod model.AuthSetUpdate) error

	// deletes all auth sets for device
	DeleteAuthSetsForDevice(devid string) error

	// adds JWT to database
	AddToken(t model.Token) error

	// retrieves JWT from database using JWT Id and device Id
	// returns ErrTokenNotFound if token not found
	GetToken(jti string) (*model.Token, error)

	// deletes token
	DeleteToken(jti string) error

	// deletes device token
	DeleteTokenByDevId(dev_id string) error

	log.ContextLogger
}
