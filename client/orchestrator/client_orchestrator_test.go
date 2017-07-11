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
package orchestrator

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	ct "github.com/mendersoftware/deviceauth/client/testing"
)

func TestGetClient(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{
		OrchestratorAddr: "localhost:6666",
	})
	assert.NotNil(t, c)
}

func TestClientReqSuccess(t *testing.T) {
	t.Parallel()

	s, rd := ct.NewMockServer(http.StatusOK)
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

	s, rd := ct.NewMockServer(http.StatusBadRequest)
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
