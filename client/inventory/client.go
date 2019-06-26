// Copyright 2019 Northern.tech AS
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
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/utils"
)

const (
	urlPatchAttrs = "/api/internal/v2/inventory/devices/:id"
	timeout       = 10 * time.Second
)

type Client interface {
	PatchDeviceV2(ctx context.Context, did, tid, src string, ts int64, attrs []Attribute) error
}

type client struct {
	client  *http.Client
	urlBase string
	verbose string
}

func NewClient(urlBase string, skipVerify bool) *client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}

	return &client{
		client: &http.Client{
			Transport: tr,
		},
		urlBase: urlBase,
	}
}

func (c *client) PatchDeviceV2(ctx context.Context, did, tid, src string, ts int64, attrs []Attribute) error {
	l := log.FromContext(ctx)

	body, err := json.Marshal(attrs)
	if err != nil {
		return errors.Wrapf(err, "failed to serialize attributes %v", attrs)
	}

	rd := bytes.NewReader(body)

	url := utils.JoinURL(c.urlBase, urlPatchAttrs)
	url = strings.Replace(url, ":id", did, 1)

	req, err := http.NewRequest(http.MethodPatch, url, rd)
	if err != nil {
		return errors.Wrapf(err, "failed to create request")
	}

	req.Header.Set("X-MEN-Source", src)
	req.Header.Set("X-MEN-Msg-Timestamp", string(ts))

	if tid != "" {
		q := req.URL.Query()
		q.Add("tenant_id", tid)
		req.URL.RawQuery = q.Encode()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rsp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return errors.Wrapf(err, "failed to submit %s %s", req.Method, req.URL)
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			body = []byte("<failed to read>")
		}
		l.Errorf("request %s %s failed with status %v, response: %s",
			req.Method, req.URL, rsp.Status, body)

		return errors.Errorf(
			"%s %s request failed with status %v", req.Method, req.URL, rsp.Status)
	}

	return nil
}
