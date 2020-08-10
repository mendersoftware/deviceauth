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
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	ct "github.com/mendersoftware/deviceauth/client/testing"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
)

func TestGetClient(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{
		OrchestratorAddr: "localhost:6666",
	})
	assert.NotNil(t, c)
}

func TestCheckHealth(t *testing.T) {
	t.Parallel()

	expiredCtx, cancel := context.WithDeadline(
		context.TODO(), time.Now().Add(-1*time.Second))
	defer cancel()
	defaultCtx, cancel := context.WithTimeout(context.TODO(), time.Second*10)
	defer cancel()

	testCases := []struct {
		Name string

		Ctx context.Context

		// Workflows response
		ResponseCode int
		ResponseBody interface{}

		Error error
	}{{
		Name: "ok",

		Ctx:          defaultCtx,
		ResponseCode: http.StatusOK,
	}, {
		Name: "error, expired deadline",

		Ctx:   expiredCtx,
		Error: errors.New(context.DeadlineExceeded.Error()),
	}, {
		Name: "error, workflows unhealthy",

		ResponseCode: http.StatusServiceUnavailable,
		ResponseBody: rest_utils.ApiError{
			Err:   "internal error",
			ReqId: "test",
		},

		Error: errors.New("internal error"),
	}, {
		Name: "error, bad response",

		Ctx: context.TODO(),

		ResponseCode: http.StatusServiceUnavailable,
		ResponseBody: "potato",

		Error: errors.New("health check HTTP error: 503 Service Unavailable"),
	}}

	responses := make(chan http.Response, 1)
	serveHTTP := func(w http.ResponseWriter, r *http.Request) {
		rsp := <-responses
		w.WriteHeader(rsp.StatusCode)
		if rsp.Body != nil {
			io.Copy(w, rsp.Body)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(serveHTTP))
	client := NewClient(Config{OrchestratorAddr: srv.URL})
	defer srv.Close()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {

			if tc.ResponseCode > 0 {
				rsp := http.Response{
					StatusCode: tc.ResponseCode,
				}
				if tc.ResponseBody != nil {
					b, _ := json.Marshal(tc.ResponseBody)
					rsp.Body = ioutil.NopCloser(bytes.NewReader(b))
				}
				responses <- rsp
			}

			err := client.CheckHealth(tc.Ctx)

			if tc.Error != nil {
				assert.Contains(t, err.Error(), tc.Error.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClientReqSuccess(t *testing.T) {
	t.Parallel()

	s, rd := ct.NewMockServer(http.StatusOK, nil)
	defer s.Close()

	c := NewClient(Config{
		OrchestratorAddr: s.URL,
	})

	ctx := context.Background()

	err := c.SubmitDeviceDecommisioningJob(ctx, DecommissioningReq{})
	assert.NoError(t, err, "expected no errors")
	assert.Equal(t, DeviceDecommissioningOrchestratorUri, rd.Url.Path)
}

func TestClientReqFail(t *testing.T) {
	t.Parallel()

	s, rd := ct.NewMockServer(http.StatusBadRequest, nil)
	defer s.Close()

	c := NewClient(Config{
		OrchestratorAddr: s.URL,
	})

	ctx := context.Background()

	err := c.SubmitDeviceDecommisioningJob(ctx, DecommissioningReq{})
	assert.Error(t, err, "expected an error")
	assert.Equal(t, DeviceDecommissioningOrchestratorUri, rd.Url.Path)
}

func TestClientReqNoHost(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{
		OrchestratorAddr: "http://somehost:1234",
	})

	ctx := context.Background()

	err := c.SubmitDeviceDecommisioningJob(ctx, DecommissioningReq{})

	assert.Error(t, err, "expected an error")
}
