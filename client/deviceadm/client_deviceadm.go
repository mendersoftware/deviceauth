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
package deviceadm

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
	defaultReqTimeout = time.Duration(10) * time.Second
)

// ClientConfig conveys client configuration
type ClientConfig struct {
	// Device admission host
	DevAdmAddr string
	// Request timeout
	Timeout time.Duration
}

// ClientRunner is an interface of device admission client
type ClientRunner interface {
	AddDevice(req AdmReq, client requestid.ApiRequester) error
	log.ContextLogger
}

// Client is an opaque implementation of device admission client. Implements
// ClientRunner interface
type Client struct {
	log  *log.Logger
	conf ClientConfig
}

func (d *Client) AddDevice(admreq AdmReq, client requestid.ApiRequester) error {
	d.log.Debugf("add device %s for admission", admreq.DeviceId)

	AdmReqJson, err := json.Marshal(admreq)
	if err != nil {
		return errors.Wrapf(err, "failed to prepare device admission request")
	}

	contentReader := bytes.NewReader(AdmReqJson)

	req, err := http.NewRequest(
		http.MethodPut,
		utils.JoinURL(d.conf.DevAdmAddr, DevAdmDevicesUri+admreq.AuthId),
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

func (d *Client) UseLog(l *log.Logger) {
	d.log = l.F(log.Ctx{})
}

func NewClientWithLogger(c ClientConfig, l *log.Logger) *Client {
	l = l.F(log.Ctx{})
	client := NewClient(c)
	client.UseLog(l)
	return client
}

func NewClient(c ClientConfig) *Client {
	if c.Timeout == 0 {
		c.Timeout = defaultReqTimeout
	}

	return &Client{
		log:  log.New(log.Ctx{}),
		conf: c,
	}
}
