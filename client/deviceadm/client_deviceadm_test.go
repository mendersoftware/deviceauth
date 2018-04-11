// Copyright 2018 Northern.tech AS
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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	ct "github.com/mendersoftware/deviceauth/client/testing"
)

func TestGetClient(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{
		DevAdmAddr: "localhost:3333",
	})
	assert.NotNil(t, c)
}

func TestClientAddDeviceSuccess(t *testing.T) {
	t.Parallel()

	s, rd := ct.NewMockServer(http.StatusNoContent, nil)
	defer s.Close()

	c := NewClient(Config{
		DevAdmAddr: s.URL,
	})

	ctx := context.Background()

	err := c.AddDevice(ctx, AdmReq{}, &http.Client{})
	assert.NoError(t, err, "expected no errors")
	assert.Equal(t, DevAdmDevicesUri, rd.Url.Path)
}

func TestClientAddDeviceFail(t *testing.T) {
	t.Parallel()

	s, rd := ct.NewMockServer(http.StatusBadRequest, nil)
	defer s.Close()

	c := NewClient(Config{
		DevAdmAddr: s.URL,
	})

	ctx := context.Background()

	err := c.AddDevice(ctx, AdmReq{}, &http.Client{})
	assert.Error(t, err, "expected an error")
	assert.Equal(t, DevAdmDevicesUri, rd.Url.Path)
}

func TestClientAddDeviceNoHost(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{
		DevAdmAddr: "http://somehost:1234",
	})

	ctx := context.Background()

	err := c.AddDevice(ctx, AdmReq{}, &http.Client{})

	assert.Error(t, err, "expected an error")
}

func TestClientAddDeviceTimeout(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// channel for nofitying the responder that the test is
	// complete
	testdone := make(chan bool)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// wait for the test to notify us about timeout
		select {
		case <-testdone:
			// test finished, can leave now
		case <-time.After(defaultReqTimeout * 2):
			// don't block longer than default timeout * 2
		}
		w.WriteHeader(400)
	}))

	addDevUrl := s.URL + "/devices"
	c := NewClient(Config{
		DevAdmAddr: addDevUrl,
	})

	t1 := time.Now()
	ctx := context.Background()
	err := c.AddDevice(ctx, AdmReq{},
		&http.Client{Timeout: defaultReqTimeout})
	t2 := time.Now()

	// let the responder know we're done
	testdone <- true

	s.Close()

	assert.Error(t, err, "expected timeout error")
	// allow some slack in timeout, add 20% of the default timeout
	maxdur := defaultReqTimeout +
		time.Duration(0.2*float64(defaultReqTimeout))

	assert.WithinDuration(t, t2, t1, maxdur, "timeout took too long")
}

func TestClientUpdateStatusInternalSuccess(t *testing.T) {
	t.Parallel()

	s, rd := ct.NewMockServer(http.StatusOK, nil)
	defer s.Close()

	c := NewClient(Config{
		DevAdmAddr: s.URL,
	})

	ctx := context.Background()

	err := c.UpdateStatusInternal(ctx, "foo", UpdateStatusReq{}, &http.Client{})
	assert.NoError(t, err, "expected no errors")
	expUri := strings.Replace(DevAdmStatusInternalUri, ":id", "foo", 1)
	assert.Equal(t, expUri, rd.Url.Path)
}

func TestClientUpdateStatusInternalFail(t *testing.T) {
	t.Parallel()

	s, rd := ct.NewMockServer(http.StatusBadRequest, nil)
	defer s.Close()

	c := NewClient(Config{
		DevAdmAddr: s.URL,
	})

	ctx := context.Background()

	err := c.UpdateStatusInternal(ctx, "foo", UpdateStatusReq{}, &http.Client{})
	assert.Error(t, err, "expected an error")
	expUri := strings.Replace(DevAdmStatusInternalUri, ":id", "foo", 1)
	assert.Equal(t, expUri, rd.Url.Path)
}

func TestClientUpdateStatusInternalNoHost(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{
		DevAdmAddr: "http://somehost:1234",
	})

	ctx := context.Background()

	err := c.UpdateStatusInternal(ctx, "foo", UpdateStatusReq{}, &http.Client{})

	assert.Error(t, err, "expected an error")
}

func TestClientUpdateStatusInternalTimeout(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	// channel for nofitying the responder that the test is
	// complete
	testdone := make(chan bool)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// wait for the test to notify us about timeout
		select {
		case <-testdone:
			// test finished, can leave now
		case <-time.After(defaultReqTimeout * 2):
			// don't block longer than default timeout * 2
		}
		w.WriteHeader(400)
	}))

	c := NewClient(Config{
		DevAdmAddr: s.URL,
	})

	t1 := time.Now()
	ctx := context.Background()
	err := c.UpdateStatusInternal(ctx, "foo", UpdateStatusReq{}, &http.Client{Timeout: defaultReqTimeout})
	t2 := time.Now()

	// let the responder know we're done
	testdone <- true

	s.Close()

	assert.Error(t, err, "expected timeout error")
	// allow some slack in timeout, add 20% of the default timeout
	maxdur := defaultReqTimeout +
		time.Duration(0.2*float64(defaultReqTimeout))

	assert.WithinDuration(t, t2, t1, maxdur, "timeout took too long")
}
