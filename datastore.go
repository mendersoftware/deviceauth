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

var (
	// device not found
	ErrDevNotFound = errors.New("not found")
)

type DataStore interface {
	// retrieve a history of device's auth requests
	GetAuthRequests(device_id string, skip, limit int) ([]AuthReq, error)

	// retrieve device by Mender-assigned device ID
	//returns ErrDevNotFound if device not found
	GetDeviceById(id string) (*Device, error)

	// retrieve device by device public key
	// returns ErrDevNotFound if device not found
	GetDeviceByKey(key string) (*Device, error)

	AddAuthReq(r *AuthReq) error
	AddDevice(r *Device) error

	// updates a single device selected via d.Id
	// updates only set fields
	UpdateDevice(d *Device) error

	// adds JWT to database
	AddToken(t *Token) error

	// retrieves JWT from database using JWT Id and device Id
	// returns ErrTokenNotFound if token not found
	GetToken(jti string) (*Token, error)
}
