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

type MockDataStore struct {
	mockGetAuthRequests func(device_id string, skip, limit int) ([]AuthReq, error)
	mockGetDeviceById   func(id string) (*Device, error)
	mockGetDeviceByKey  func(key string) (*Device, error)
	mockAddAuthReq      func(r *AuthReq) error
	mockAddDevice       func(r *Device) error
	mockUpdateDevice    func(d *Device) error
}

func (db *MockDataStore) GetAuthRequests(dev_id string, skip, limit int) ([]AuthReq, error) {
	return db.mockGetAuthRequests(dev_id, skip, limit)
}

func (db *MockDataStore) GetDeviceById(id string) (*Device, error) {
	return db.mockGetDeviceById(id)
}

func (db *MockDataStore) GetDeviceByKey(key string) (*Device, error) {
	return db.mockGetDeviceByKey(key)
}

func (db *MockDataStore) AddAuthReq(r *AuthReq) error {
	return db.mockAddAuthReq(r)
}

func (db *MockDataStore) AddDevice(d *Device) error {
	return db.mockAddDevice(d)
}

func (db *MockDataStore) UpdateDevice(d *Device) error {
	return db.mockUpdateDevice(d)
}
