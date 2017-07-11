// Copyright 2017 Northern.tech AS
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
package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/utils"
)

const (
	// devices endpoint
	InventoryDevicesUri = "/api/0.1.0/devices"
	// default request timeout, 10s?
	defaultReqTimeout = time.Duration(10) * time.Second
)

// ClientConfig conveys client configuration
type Config struct {
	// Inventory service address
	InventoryAddr string
	// Request timeout
	Timeout time.Duration
}

// ClientRunner is an interface of inventory client
type ClientRunner interface {
	AddDevice(ctx context.Context, req AddReq, client apiclient.HttpRunner) error
}

// Client is an opaque implementation of inventory client. Implements
// ClientRunner interface
type Client struct {
	conf Config
}

// AddReq contains request data of request to add a device.
type AddReq struct {
	// Device ID
	Id string `json:"id"`
}

func (ic *Client) AddDevice(ctx context.Context, areq AddReq, client apiclient.HttpRunner) error {

	l := log.FromContext(ctx)

	l.Debugf("add device %s to inventory", areq.Id)

	ireq, err := json.Marshal(areq)
	if err != nil {
		return errors.Wrapf(err, "failed to prepare device admission request")
	}

	contentReader := bytes.NewReader(ireq)

	req, err := http.NewRequest(
		http.MethodPost,
		utils.JoinURL(ic.conf.InventoryAddr, InventoryDevicesUri),
		contentReader)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Set("Content-Type", "application/json")

	// set the inventory request timeout
	ctx, cancel := context.WithTimeout(ctx, ic.conf.Timeout)
	defer cancel()

	rsp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrapf(err, "failed to add device")
	}
	defer rsp.Body.Close()

	switch rsp.StatusCode {
	case http.StatusConflict:
		l.Warnf("inventory entry for device %s already exists", areq.Id)
	case http.StatusCreated:
		l.Infof("inventory entry for device %s created", areq.Id)
	default:
		l.Errorf("failed to create inventory entry for device")
		if err == nil {
			err = errors.New("unexpected response status")
		}
		return errors.Wrapf(err,
			"device add request failed with status %v", rsp.Status)
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
