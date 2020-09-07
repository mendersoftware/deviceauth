// Copyright 2020 Northern.tech AS
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
package model

import (
	"time"

	"github.com/mendersoftware/go-lib-micro/ratelimits"
)

const (
	DevStatusAccepted = "accepted"
	DevStatusRejected = "rejected"
	DevStatusPending  = "pending"
	DevStatusPreauth  = "preauthorized"
	DevStatusNoAuth   = "noauth"

	DevKeyIdData       = "id_data"
	DevKeyIdDataSha256 = "id_data_sha256"
	DevKeyStatus       = "status"
)

// note: fields with underscores need the 'bson' decorator
// otherwise the underscore will be removed upon write to mongo
type Device struct {
	Id              string                 `json:"id" bson:"_id,omitempty"`
	PubKey          string                 `json:"-" bson:",omitempty"`
	IdData          string                 `json:"id_data" bson:"id_data,omitempty"`
	IdDataStruct    map[string]interface{} `bson:"id_data_struct,omitempty"`
	IdDataSha256    []byte                 `bson:"id_data_sha256,omitempty"`
	Status          string                 `json:"-" bson:",omitempty"`
	Decommissioning bool                   `json:"decommissioning" bson:",omitempty"`
	CreatedTs       time.Time              `json:"created_ts" bson:"created_ts,omitempty"`
	UpdatedTs       time.Time              `json:"updated_ts" bson:"updated_ts,omitempty"`
	AuthSets        []AuthSet              `json:"auth_sets" bson:"-"`
	//ApiLimits override tenant-wide quota/burst config
	ApiLimits ratelimits.ApiLimits `json:"-" bson:"api_limits"`
}

type DeviceUpdate struct {
	PubKey          string                 `json:"-" bson:",omitempty"`
	IdData          string                 `json:"id_data" bson:"id_data,omitempty"`
	IdDataStruct    map[string]interface{} `bson:"id_data_struct,omitempty"`
	IdDataSha256    []byte                 `bson:"id_data_sha256,omitempty"`
	Status          string                 `json:"-" bson:",omitempty"`
	Decommissioning *bool                  `json:"-" bson:",omitempty"`
	UpdatedTs       *time.Time             `json:"updated_ts" bson:"updated_ts,omitempty"`
}

func NewDevice(id, id_data, pubkey string) *Device {
	now := time.Now()

	return &Device{
		Id:              id,
		IdData:          id_data,
		PubKey:          pubkey,
		Status:          DevStatusPending,
		Decommissioning: false,
		CreatedTs:       now,
		UpdatedTs:       now,
	}
}
