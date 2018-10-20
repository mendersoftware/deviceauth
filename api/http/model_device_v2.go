// Copyright 2018 Northern.tech AS
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
package http

import (
	"time"

	"github.com/mendersoftware/deviceauth/model"
)

type deviceV2 struct {
	Id              string                 `json:"id"`
	IdData          map[string]interface{} `json:"identity_data"`
	Status          string                 `json:"status"`
	Decommissioning bool                   `json:"decommissioning"`
	CreatedTs       time.Time              `json:"created_ts"`
	UpdatedTs       time.Time              `json:"updated_ts"`
	AuthSets        []authSetV2            `json:"auth_sets"`
}

func deviceV2FromDbModel(dbDevice *model.Device) (*deviceV2, error) {
	authSets, err := authSetsV2FromDbModel(dbDevice.AuthSets)
	if err != nil {
		return nil, err
	}
	return &deviceV2{
		Id:              dbDevice.Id,
		IdData:          dbDevice.IdDataStruct,
		Status:          dbDevice.Status,
		Decommissioning: dbDevice.Decommissioning,
		CreatedTs:       dbDevice.CreatedTs,
		UpdatedTs:       dbDevice.UpdatedTs,
		AuthSets:        authSets,
	}, nil
}

func devicesV2FromDbModel(dbDevices []model.Device) ([]deviceV2, error) {
	devicesList := make([]deviceV2, len(dbDevices))
	for i, d := range dbDevices {
		devV2, err := deviceV2FromDbModel(&d)
		if err != nil {
			return nil, err
		}
		devicesList[i] = *devV2
	}

	return devicesList, nil
}
