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

type authSetV2 struct {
	Id        string                 `json:"id"`
	IdData    map[string]interface{} `json:"identity_data"`
	PubKey    string                 `json:"pubkey"`
	Timestamp *time.Time             `json:"ts"`
	Status    string                 `json:"status"`
}

func authSetV2FromDbModel(dbAuthSet *model.AuthSet) (*authSetV2, error) {
	return &authSetV2{
		Id:        dbAuthSet.Id,
		IdData:    dbAuthSet.IdDataStruct,
		PubKey:    dbAuthSet.PubKey,
		Timestamp: dbAuthSet.Timestamp,
		Status:    dbAuthSet.Status,
	}, nil
}

func authSetsV2FromDbModel(dbAuthSets []model.AuthSet) ([]authSetV2, error) {
	authSetsList := make([]authSetV2, len(dbAuthSets))
	for i, d := range dbAuthSets {
		asV2, err := authSetV2FromDbModel(&d)
		if err != nil {
			return nil, err
		}
		authSetsList[i] = *asV2
	}

	return authSetsList, nil
}
