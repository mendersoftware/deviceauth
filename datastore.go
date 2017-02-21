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

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
)

var (
	// device not found
	ErrDevNotFound = errors.New("device not found")
	// device not found
	ErrTokenNotFound = errors.New("token not found")
)

type DataStore interface {
	// retrieve device by Mender-assigned device ID
	//returns ErrDevNotFound if device not found
	GetDeviceById(id string) (*Device, error)

	// retrieve device by device public key
	// returns ErrDevNotFound if device not found
	GetDeviceByKey(key string) (*Device, error)

	// list devices
	GetDevices(skip, limit uint) ([]Device, error)

	AddDevice(r *Device) error

	// updates a single device selected via d.Id
	// updates only set fields
	UpdateDevice(d *Device) error

	// adds JWT to database
	AddToken(t *Token) error

	// retrieves JWT from database using JWT Id and device Id
	// returns ErrTokenNotFound if token not found
	GetToken(jti string) (*Token, error)

	// deletes token
	DeleteToken(jti string) error

	// deletes device token
	DeleteTokenByDevId(dev_id string) error

	// run migrations
	Migrate(version string, migrations []migrate.Migration) error

	log.ContextLogger
}
