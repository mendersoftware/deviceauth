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
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/model"
	"github.com/mendersoftware/deviceauth/utils"
)

const (
	// orchestrator endpoint
	DeviceDecommissioningOrchestratorUri = "/api/v1/workflow/decommission_device"
	ProvisionDeviceOrchestratorUri       = "/api/v1/workflow/provision_device"
	// default request timeout, 10s?
	defaultReqTimeout = time.Duration(10) * time.Second
)

// DecomissioningReq contains request data of request to start decommissioning workflow
type DecommissioningReq struct {
	// Device ID
	DeviceId string `json:"device_id"`
	// Request ID
	RequestId string `json:"request_id"`
	// User authorization, eg. the value of Authorization header of incoming
	// HTTP request
	Authorization string `json:"authorization"`
}

// ProvisionDeviceReq contains request data of request to start provisioning workflow
type ProvisionDeviceReq struct {
	// Request ID
	RequestId string `json:"request_id"`
	// User authorization, eg. the value of Authorization header of incoming
	// HTTP request
	Authorization string `json:"authorization"`
	// Device
	Device model.Device `json:"device"`
}

// Config conveys client configuration
type Config struct {
	// Orchestrator host
	OrchestratorAddr string
	// Request timeout
	Timeout time.Duration
}

// ClientRunner is an interface of orchestrator client
type ClientRunner interface {
	SubmitDeviceDecommisioningJob(ctx context.Context, req DecommissioningReq) error
	SubmitProvisionDeviceJob(ctx context.Context, req ProvisionDeviceReq) error
}

// Client is an opaque implementation of orchestrator client. Implements
// ClientRunner interface
type Client struct {
	conf Config
}

func (co *Client) SubmitDeviceDecommisioningJob(ctx context.Context, decommissioningReq DecommissioningReq) error {

	l := log.FromContext(ctx)
	client := http.Client{}

	l.Debugf("Submit decommissioning job for device: %s", decommissioningReq.DeviceId)

	DecommissioningReqJson, err := json.Marshal(decommissioningReq)
	if err != nil {
		return errors.Wrapf(err, "failed to submit device decommissioning job")
	}

	contentReader := bytes.NewReader(DecommissioningReqJson)

	req, err := http.NewRequest(
		http.MethodPost,
		utils.JoinURL(co.conf.OrchestratorAddr, DeviceDecommissioningOrchestratorUri),
		contentReader)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/json")

	// set the device admission request timeout
	ctx, cancel := context.WithTimeout(ctx, co.conf.Timeout)
	defer cancel()

	rsp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrapf(err, "failed to submit decommissioning job")
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			body = []byte("<failed to read>")
		}
		l.Errorf("decommision request %s %s failed with status %v, response text: %s",
			req.Method, req.URL, rsp.Status, body)

		return errors.Errorf(
			"submit decommissioning request failed with status %v", rsp.Status)
	}
	return nil
}

func (co *Client) SubmitProvisionDeviceJob(ctx context.Context, provisionDeviceReq ProvisionDeviceReq) error {

	l := log.FromContext(ctx)
	client := http.Client{}

	l.Debugf("Submit provision device job for device: %s", provisionDeviceReq.Device.Id)

	ProvisionDeviceReqJson, err := json.Marshal(provisionDeviceReq)
	if err != nil {
		return errors.Wrapf(err, "failed to submit provision device job")
	}

	contentReader := bytes.NewReader(ProvisionDeviceReqJson)

	req, err := http.NewRequest(
		http.MethodPost,
		utils.JoinURL(co.conf.OrchestratorAddr, ProvisionDeviceOrchestratorUri),
		contentReader)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/json")

	// set the device admission request timeout
	ctx, cancel := context.WithTimeout(ctx, co.conf.Timeout)
	defer cancel()

	rsp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrapf(err, "failed to submit provision device job")
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusCreated {
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			body = []byte("<failed to read>")
		}
		l.Errorf("provision device request %s %s failed with status %v, response text: %s",
			req.Method, req.URL, rsp.Status, body)

		return errors.Errorf(
			"submit provision device request failed with status %v", rsp.Status)
	}
	return nil
}

func NewClient(c Config) *Client {
	if c.Timeout == 0 {
		c.Timeout = defaultReqTimeout
	}

	return &Client{
		conf: c,
	}
}
