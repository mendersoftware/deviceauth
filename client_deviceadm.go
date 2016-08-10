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
	"time"
)

const (
	// default devices endpoint
	defaultDevAdmDevicesUri = "/devices"
	// default request timeout, 10s?
	defaultDevAdmReqTimeout = time.Duration(10) * time.Second
)

type DevAdmClientConfig struct {
	// device add URL
	AddDeviceUrl string
	// request timeout
	Timeout time.Duration
}

type DevAdmClientI interface {
	AddDevice(dev *Device, client requestid.ApiRequester) error
	log.ContextLogger
}

type DevAdmClient struct {
	log  *log.Logger
	conf DevAdmClientConfig
}

func (d *DevAdmClient) AddDevice(dev *Device, client requestid.ApiRequester) error {
	d.log.Debugf("add device %s for admission", dev.Id)

	AdmReqJson, err := json.Marshal(AdmReq{
		Id:     dev.Id,
		IdData: dev.IdData,
		PubKey: dev.PubKey,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to prepare device admission request")
	}

	contentReader := bytes.NewReader(AdmReqJson)

	req, err := http.NewRequest(
		http.MethodPost, d.conf.AddDeviceUrl, contentReader)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/json")

	rsp, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to add device")
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusCreated {
		return errors.Wrapf(err,
			"device add request failed with status %v", rsp.Status)
	}
	return nil
}

func (d *DevAdmClient) UseLog(l *log.Logger) {
	d.log = l.F(log.Ctx{LogModule: "client_deviceadm"})
}

func GetDevAdmClient(c DevAdmClientConfig, l *log.Logger) *DevAdmClient {
	l = l.F(log.Ctx{LogModule: "client_deviceadm"})
	client := NewDevAdmClient(c)
	client.UseLog(l)
	return client
}

func NewDevAdmClient(c DevAdmClientConfig) *DevAdmClient {
	if c.Timeout == 0 {
		c.Timeout = defaultDevAdmReqTimeout
	}

	return &DevAdmClient{
		log:  log.New(log.Ctx{LogModule: "client_deviceadm"}),
		conf: c,
	}
}
