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
package model

import (
	"time"
)

const (
	AuthSetKeyIdData   = "id_data"
	AuthSetKeyPubKey   = "pubkey"
	AuthSetKeyDeviceId = "device_id"
)

type AuthSet struct {
	Id                string     `json:"id" bson:"_id,omitempty"`
	IdData            string     `json:"id_data" bson:"id_data,omitempty"`
	TenantToken       string     `json:"tenant_token" bson:"tenant_token,omitempty"`
	PubKey            string     `json:"pubkey" bson:"pubkey,omitempty"`
	DeviceId          string     `json:"-" bson:"device_id,omitempty"`
	Timestamp         *time.Time `json:"ts" bson:"ts,omitempty"`
	Status            string     `json:"status" bson:"status,omitempty"`
	AdmissionNotified *bool      `json:"-" bson:"admission_notified,omitempty"`
}

type AuthSetUpdate struct {
	IdData            string     `bson:"id_data,omitempty"`
	TenantToken       string     `bson:"tenant_token,omitempty"`
	PubKey            string     `bson:"pubkey,omitempty"`
	DeviceId          string     `bson:"device_id,omitempty"`
	Timestamp         *time.Time `bson:"ts,omitempty"`
	Status            string     `bson:"status,omitempty"`
	AdmissionNotified *bool      `bson:"admission_notified,omitempty"`
}
