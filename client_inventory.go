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
	"bytes"
	"encoding/json"
	"github.com/mendersoftware/deviceauth/log"
	"github.com/mendersoftware/deviceauth/requestid"
	"github.com/pkg/errors"
	"net/http"
)

type InventoryClientConfig struct {
	// device add URL
	AddDeviceUrl string
}

type InventoryClientI interface {
	AddDevice(dev *Device, client requestid.ApiRequester) error
	log.ContextLogger
}

type InventoryClient struct {
	log  *log.Logger
	conf InventoryClientConfig
}

type InventoryAddReq struct {
	Id string `json:"id"`
}

func (ic *InventoryClient) AddDevice(dev *Device, client requestid.ApiRequester) error {
	ic.log.Debugf("add device %s to inventory", dev.Id)

	ireq, err := json.Marshal(InventoryAddReq{
		Id: dev.Id,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to prepare device admission request")
	}

	contentReader := bytes.NewReader(ireq)

	req, err := http.NewRequest(
		http.MethodPost, ic.conf.AddDeviceUrl, contentReader)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/json")

	rsp, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to add device")
	}
	defer rsp.Body.Close()

	switch rsp.StatusCode {
	case http.StatusConflict:
		ic.log.Warnf("inventory entry for device %s already exists", dev.Id)
	case http.StatusCreated:
		ic.log.Infof("inventory entry for device %s created", dev.Id)
	default:
		ic.log.Errorf("failed to create inventory entry for device")
		if err == nil {
			err = errors.New("unexpected response status")
		}
		return errors.Wrapf(err,
			"device add request failed with status %v", rsp.Status)
	}
	return nil
}

func (ic *InventoryClient) UseLog(l *log.Logger) {
	ic.log = l.F(log.Ctx{})
}

func NewInventoryClientWithLogger(c InventoryClientConfig, l *log.Logger) *InventoryClient {
	l = l.F(log.Ctx{})
	client := NewInventoryClient(c)
	client.UseLog(l)
	return client
}

func NewInventoryClient(c InventoryClientConfig) *InventoryClient {
	return &InventoryClient{
		log:  log.New(log.Ctx{}),
		conf: c,
	}
}
