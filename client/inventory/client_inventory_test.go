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
package inventory

import (
	"fmt"
	"net/http"
	"testing"

	ct "github.com/mendersoftware/deviceauth/client/testing"
	"github.com/mendersoftware/deviceauth/model"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestClientGet(t *testing.T) {
	t.Parallel()

	c := NewClientWithLogger(ClientConfig{InventoryAddr: "http://foo"},
		log.New(log.Ctx{}))
	assert.NotNil(t, c)
}

func TestClient(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		status int
		dev    model.Device
		expReq string
		err    error
	}{
		{
			status: http.StatusCreated,
			dev:    model.Device{Id: "1234"},
			expReq: `{"id": "1234"}`,
			err:    nil,
		},
		{
			// 409 Conflict is treated as success
			status: http.StatusConflict,
			dev:    model.Device{Id: "1234"},
			expReq: `{"id": "1234"}`,
			err:    nil,
		},
		{
			status: http.StatusOK,
			dev:    model.Device{Id: "1234"},
			expReq: `{"id": "1234"}`,
			err:    errors.New("device add request failed with status 200 OK: unexpected response status"),
		},
		{
			status: http.StatusBadRequest,
			dev:    model.Device{Id: "1234"},
			expReq: `{"id": "1234"}`,
			err:    errors.New("device add request failed with status 400 Bad Request: unexpected response status"),
		},
	}

	for i := range tcs {
		tc := tcs[i]
		t.Run(fmt.Sprintf("case %v %s", tc.status, tc.expReq), func(t *testing.T) {
			t.Parallel()

			s, rd := ct.NewMockServer(tc.status)

			c := NewClient(ClientConfig{
				InventoryAddr: s.URL,
			})

			err := c.AddDevice(AddReq{Id: "1234"}, &http.Client{})
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				assert.JSONEq(t, tc.expReq, string(rd.ReqBody))
				assert.Equal(t, InventoryDevicesUri, rd.Url.Path)
			}
			s.Close()
		})
	}
}
