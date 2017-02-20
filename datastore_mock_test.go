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
	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/go-lib-micro/mongo/migrate"
)

type MockDataStore struct {
	mockGetDevices         func(skip, limit uint) ([]Device, error)
	mockGetDeviceById      func(id string) (*Device, error)
	mockGetDeviceByKey     func(key string) (*Device, error)
	mockAddDevice          func(r *Device) error
	mockUpdateDevice       func(d *Device) error
	mockAddToken           func(t *Token) error
	mockGetToken           func(jti string) (*Token, error)
	mockDeleteToken        func(jti string) error
	mockDeleteTokenByDevId func(dev_id string) error
	mockSet                func(l log.Logger)
}

func (db *MockDataStore) GetDeviceById(id string) (*Device, error) {
	return db.mockGetDeviceById(id)
}

func (db *MockDataStore) GetDevices(skip, limit uint) ([]Device, error) {
	return db.mockGetDevices(skip, limit)
}

func (db *MockDataStore) GetDeviceByKey(key string) (*Device, error) {
	return db.mockGetDeviceByKey(key)
}

func (db *MockDataStore) AddDevice(d *Device) error {
	return db.mockAddDevice(d)
}

func (db *MockDataStore) UpdateDevice(d *Device) error {
	return db.mockUpdateDevice(d)
}

func (db *MockDataStore) AddToken(t *Token) error {
	return db.mockAddToken(t)
}

func (db *MockDataStore) GetToken(jti string) (*Token, error) {
	return db.mockGetToken(jti)
}

func (db *MockDataStore) DeleteToken(jti string) error {
	return db.mockDeleteToken(jti)
}

func (db *MockDataStore) DeleteTokenByDevId(dev_id string) error {
	return db.mockDeleteTokenByDevId(dev_id)
}

func (db *MockDataStore) Migrate(version string, migrations []migrate.Migration) error {
	// nop
	return nil
}

func (db *MockDataStore) UseLog(l *log.Logger) {
	//nop
}
