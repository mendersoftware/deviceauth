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
	"github.com/mendersoftware/deviceauth/log"
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

type DevAdmClient struct {
	client http.Client
	log    *log.Logger
	conf   DevAdmClientConfig
}

func (d *DevAdmClient) AddDevice(dev Device) error {
	d.log.Debugf("add device %s for admission", dev.Id)

	req, err := http.NewRequest(http.MethodPut, d.conf.AddUrl, nil)

	// TODO: prepare message

	rsp, err := d.client.Do(req)
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

func NewDevAdmClient(c DevAdmClientConfig) *DevAdmClient {
	if c.Timeout == 0 {
		c.Timeout = defaultDevAdmReqTimeout
	}

	return &DevAdmClient{
		client: http.Client{
			// request timeout
			Timeout: c.Timeout,
		},
		log:  log.New("devadm-client"),
		conf: c,
	}
}
