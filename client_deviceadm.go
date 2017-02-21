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
	"net/http"
	"time"

	"github.com/mendersoftware/deviceauth/utils"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
	"github.com/pkg/errors"
)

const (
	// devices endpoint
	DevAdmDevicesUri = "/api/0.1.0/devices/"
	// default request timeout, 10s?
	defaultDevAdmReqTimeout = time.Duration(10) * time.Second
)

type DevAdmClientConfig struct {
	// device add URL
	DevAdmAddr string
	// request timeout
	Timeout time.Duration
}

type DevAdmClient interface {
	AddDevice(dev *Device, client requestid.ApiRequester) error
	log.ContextLogger
}

type devAdmClient struct {
	log  *log.Logger
	conf DevAdmClientConfig
}

func (d *devAdmClient) AddDevice(dev *Device, client requestid.ApiRequester) error {
	d.log.Debugf("add device %s for admission", dev.Id)

	AdmReqJson, err := json.Marshal(AdmReq{
		IdData: dev.IdData,
		PubKey: dev.PubKey,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to prepare device admission request")
	}

	contentReader := bytes.NewReader(AdmReqJson)

	req, err := http.NewRequest(
		http.MethodPut,
		utils.JoinURL(d.conf.DevAdmAddr, DevAdmDevicesUri+dev.Id),
		contentReader)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/json")

	rsp, err := client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "failed to add device")
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusNoContent {
		return errors.Errorf(
			"device add request failed with status %v", rsp.Status)
	}
	return nil
}

func (d *devAdmClient) UseLog(l *log.Logger) {
	d.log = l.F(log.Ctx{})
}

func GetDevAdmClient(c DevAdmClientConfig, l *log.Logger) *devAdmClient {
	l = l.F(log.Ctx{})
	client := NewDevAdmClient(c)
	client.UseLog(l)
	return client
}

func NewDevAdmClient(c DevAdmClientConfig) *devAdmClient {
	if c.Timeout == 0 {
		c.Timeout = defaultDevAdmReqTimeout
	}

	return &devAdmClient{
		log:  log.New(log.Ctx{}),
		conf: c,
	}
}
