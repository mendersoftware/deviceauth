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
package model

import (
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"time"

	"github.com/asaskevich/govalidator"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
	"github.com/mendersoftware/go-lib-micro/ratelimits"
	"github.com/pkg/errors"
)

const (
	DevStatusAccepted = "accepted"
	DevStatusRejected = "rejected"
	DevStatusPending  = "pending"
	DevStatusPreauth  = "preauthorized"
	DevStatusNoAuth   = "noauth"

	DevKeyId           = "_id"
	DevKeyIdData       = "id_data"
	DevKeyIdDataSha256 = "id_data_sha256"
	DevKeyStatus       = "status"
)

var (
	DevStatuses = []string{
		DevStatusPending,
		DevStatusRejected,
		DevStatusAccepted,
		DevStatusPreauth,
		DevStatusNoAuth,
	}
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
	External        *ExternalDevice        `json:"external,omitempty" bson:"external,omitempty"`
	//ApiLimits override tenant-wide quota/burst config
	ApiLimits ratelimits.ApiLimits `json:"-" bson:"api_limits"`

	//object revision which we use when synchronizint status with inventory service
	Revision uint `json:"-" bson:"revision"`
}

type ExternalDevice struct {
	ID       string `json:"id" bson:"id"`
	Provider string `json:"provider" bson:"provider"`
	Name     string `json:"name,omitempty" bson:"name,omitempty"`
}

func (ext ExternalDevice) Validate() error {
	return validation.ValidateStruct(&ext,
		validation.Field(&ext.ID, validation.Required),
		validation.Field(&ext.Provider, validation.Required),
		validation.Field(&ext.Name, validation.Required),
	)
}

func (ext ExternalDevice) IDData() map[string]interface{} {
	m := map[string]interface{}{
		"external_id":       ext.ID,
		"external_provider": ext.Provider,
	}
	if ext.Name != "" {
		m["external_name"] = ext.Name
	}

	return m
}

type ExternalDeviceRequest struct {
	ExternalDevice
	IDData map[string]interface{} `json:"id_data"`
}

func (ext ExternalDeviceRequest) Validate() error {
	return validation.ValidateStruct(&ext,
		validation.Field(&ext.ExternalDevice),
	)
}

func (ext ExternalDeviceRequest) NewDevice() *Device {
	id := uuid.New()
	var idData map[string]interface{} = ext.IDData
	if len(idData) == 0 {
		idData = ext.ExternalDevice.IDData()
	}
	b, _ := json.Marshal(idData)
	dev := NewDevice(id.String(), string(b), "")
	chksum := sha256.New()
	chksum.Write(b)
	dev.IdDataSha256 = chksum.Sum(nil)
	dev.IdDataStruct = idData
	dev.Status = DevStatusAccepted
	dev.External = &ext.ExternalDevice
	return dev
}

type DeviceUpdate struct {
	PubKey          string                 `json:"-" bson:",omitempty"`
	IdData          string                 `json:"id_data" bson:"id_data,omitempty"`
	IdDataStruct    map[string]interface{} `bson:"id_data_struct,omitempty"`
	IdDataSha256    []byte                 `bson:"id_data_sha256,omitempty"`
	Status          string                 `json:"-" bson:",omitempty"`
	Decommissioning *bool                  `json:"-" bson:",omitempty"`
	UpdatedTs       *time.Time             `json:"updated_ts" bson:"updated_ts,omitempty"`
	ExternalName    string                 `json:"external_name,omitempty" bson:"external.name,omitempty"`
}

func NewDevice(id, id_data, pubkey string) *Device {
	now := time.Now()

	return &Device{
		Id:              id,
		IdData:          id_data,
		PubKey:          pubkey,
		Status:          DevStatusNoAuth,
		Decommissioning: false,
		CreatedTs:       now,
		UpdatedTs:       now,
		Revision:        1,
	}
}

type DeviceFilter struct {
	Status []string `json:"status,omitempty"`
	IDs    []string `json:"id,omitempty"`
}

func (fltr DeviceFilter) Validate() error {
	for _, stat := range fltr.Status {
		if !govalidator.IsIn(stat, DevStatuses...) {
			return errors.Errorf(
				`filter status must be one of: `+
					`%s, %s, %s, %s or %s`,
				DevStatusAccepted, DevStatusPending,
				DevStatusRejected, DevStatusPreauth,
				DevStatusNoAuth,
			)
		}
	}
	return nil
}

func (fltr *DeviceFilter) UnmarshalJSON(b []byte) error {
	schema := struct {
		Status interface{} `json:"status"`
		IDs    interface{} `json:"id"`
	}{}

	err := json.Unmarshal(b, &schema)
	if err != nil {
		return err
	}
	switch t := schema.Status.(type) {
	case string:
		fltr.Status = []string{t}
	case []interface{}:
		fltr.Status = make([]string, 0, len(t))
		for _, elem := range t {
			if str, ok := elem.(string); ok {
				fltr.Status = append(fltr.Status, str)
			} else {
				return errors.New(
					"invalid JSON type for 'status': " +
						"must be string or []string",
				)
			}
		}
	case nil:
		break
	default:
		return errors.New(
			"invalid JSON type for 'status': " +
				"must be string or []string",
		)
	}
	switch t := schema.IDs.(type) {
	case string:
		fltr.IDs = []string{t}
	case []interface{}:
		fltr.IDs = make([]string, 0, len(t))
		for _, elem := range t {
			if str, ok := elem.(string); ok {
				fltr.IDs = append(fltr.IDs, str)
			} else {
				return errors.New(
					"invalid JSON type for 'id': " +
						"must be string or []string",
				)
			}
		}
	case nil:
		break
	default:
		return errors.New(
			"invalid JSON type for 'id': " +
				"must be string or []string",
		)
	}
	return nil
}

func (fltr *DeviceFilter) ParseForm(form url.Values) error {
	if stat, ok := form["status"]; ok {
		fltr.Status = stat
	}
	if IDs, ok := form["id"]; ok {
		fltr.IDs = IDs
	}
	return fltr.Validate()
}

type DeviceAttribute struct {
	Name        string      `json:"name" bson:",omitempty"`
	Description *string     `json:"description,omitempty" bson:",omitempty"`
	Value       interface{} `json:"value" bson:",omitempty"`
	Scope       string      `json:"scope" bson:",omitempty"`
}

type DeviceInventoryUpdate struct {
	Id       string `json:"id"`
	Revision uint   `json:"revision"`
}
