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
package http

import (
	"crypto/rsa"
	"encoding/json"
	"io"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
	"github.com/satori/go.uuid"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/utils"
)

type preAuthReq struct {
	IdData map[string]interface{} `json:"identity_data" valid:"-"`
	PubKey string                 `json:"pubkey" valid:"required"`
}

func parsePreAuthReq(source io.Reader) (*preAuthReq, error) {
	jd := json.NewDecoder(source)

	var req preAuthReq

	if err := jd.Decode(&req); err != nil {
		return nil, err
	}

	if err := req.validate(); err != nil {
		return nil, err
	}

	return &req, nil
}

func (r *preAuthReq) validate() error {
	if _, err := govalidator.ValidateStruct(*r); err != nil {
		return err
	}

	if len(r.IdData) == 0 {
		return errors.New("id_data: non zero value required;")
	}
	_, err := json.Marshal(r.IdData)
	if err != nil {
		return err
	}

	//normalize key
	key, err := utils.ParsePubKey(r.PubKey)
	if err != nil {
		return err
	}

	keyStruct, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("cannot decode public key")
	}

	serialized, err := utils.SerializePubKey(keyStruct)
	if err != nil {
		return err
	}

	r.PubKey = serialized

	return nil
}

func (r *preAuthReq) getDbModel() (*model.PreAuthReq, error) {
	enc, err := json.Marshal(r.IdData)
	if err != nil {
		return nil, err
	}

	dId := uuid.NewV4()
	asId := uuid.NewV4()

	return &model.PreAuthReq{
		DeviceId:  dId.String(),
		AuthSetId: asId.String(),
		IdData:    string(enc),
		PubKey:    r.PubKey,
	}, nil
}
