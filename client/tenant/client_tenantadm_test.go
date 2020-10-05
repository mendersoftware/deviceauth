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
package tenant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	ct "github.com/mendersoftware/deviceauth/client/testing"
	"github.com/mendersoftware/go-lib-micro/ratelimits"
)

func TestClientGet(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{TenantAdmAddr: "http://foo"})
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
	client := NewClient(Config{TenantAdmAddr: srv.URL})
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

func TestClientVerifyToken(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		tadmStatus int
		tadmBody   interface{}
		token      string

		tenant *Tenant
		err    error
	}{
		{
			tadmStatus: http.StatusBadRequest,
			err:        errors.New("token verification request returned unexpected status 400"),
		},
		{
			// try some bogus tadmStatus
			tadmStatus: http.StatusNotAcceptable,
			err:        errors.New("token verification request returned unexpected status 406"),
		},
		{
			// token verified ok
			tadmStatus: http.StatusOK,
			tadmBody: &Tenant{
				ID:     "foo",
				Name:   "foo-name",
				Status: "active",
				Plan:   "enterprise",
				ApiLimits: TenantApiLimits{
					MgmtLimits: ratelimits.ApiLimits{
						ApiBursts: []ratelimits.ApiBurst{},
					},
					DeviceLimits: ratelimits.ApiLimits{
						ApiBursts: []ratelimits.ApiBurst{},
					},
				},
			},
			tenant: &Tenant{
				ID:     "foo",
				Name:   "foo-name",
				Status: "active",
				Plan:   "enterprise",
				ApiLimits: TenantApiLimits{
					MgmtLimits: ratelimits.ApiLimits{
						ApiBursts: []ratelimits.ApiBurst{},
					},
					DeviceLimits: ratelimits.ApiLimits{
						ApiBursts: []ratelimits.ApiBurst{},
					},
				},
			},
		},
		{
			tadmStatus: http.StatusUnauthorized,
			tadmBody:   restError("account suspended"),
			err:        errors.New("tenant token verification failed: account suspended"),
		},
	}

	for i := range tcs {
		tc := tcs[i]
		t.Run(fmt.Sprintf("status %v", tc.tadmStatus), func(t *testing.T) {
			t.Parallel()

			var body []byte

			body, err := json.Marshal(tc.tadmBody)
			assert.NoError(t, err)

			s, rd := ct.NewMockServer(tc.tadmStatus, body)

			c := NewClient(Config{
				TenantAdmAddr: s.URL,
			})

			tenant, err := c.VerifyToken(context.Background(), tc.token)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, TenantVerifyUri, rd.Url.Path)
				assert.Equal(t, tc.tenant, tenant)
			}
			s.Close()
		})
	}
}

func TestClientGetTenant(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		tid        string
		tadmStatus int
		tadmBody   interface{}
		token      string

		tenant *Tenant
		err    error
	}{
		{
			tid:        "foo",
			tadmStatus: http.StatusOK,
			tadmBody: &Tenant{
				ID:     "foo",
				Name:   "tenant-foo",
				Status: "active",
				Plan:   "enterprise",
				ApiLimits: TenantApiLimits{
					MgmtLimits: ratelimits.ApiLimits{
						ApiBursts: []ratelimits.ApiBurst{},
					},
					DeviceLimits: ratelimits.ApiLimits{
						ApiQuota: ratelimits.ApiQuota{
							MaxCalls:    100,
							IntervalSec: 60,
						},
						ApiBursts: []ratelimits.ApiBurst{
							{
								Uri:            "/foo",
								MinIntervalSec: 5,
							},
						},
					},
				},
			},
			tenant: &Tenant{
				ID:     "foo",
				Name:   "tenant-foo",
				Status: "active",
				Plan:   "enterprise",
				ApiLimits: TenantApiLimits{
					MgmtLimits: ratelimits.ApiLimits{
						ApiBursts: []ratelimits.ApiBurst{},
					},
					DeviceLimits: ratelimits.ApiLimits{
						ApiQuota: ratelimits.ApiQuota{
							MaxCalls:    100,
							IntervalSec: 60,
						},
						ApiBursts: []ratelimits.ApiBurst{
							{
								Uri:            "/foo",
								MinIntervalSec: 5,
							},
						},
					},
				},
			},
		},
		{
			tadmStatus: http.StatusNotFound,
			tadmBody:   restError(""),
			tenant:     nil,
			err:        nil,
		},
		{
			tadmStatus: http.StatusInternalServerError,
			tadmBody:   restError("internal error"),
			tenant:     nil,
			err:        errors.New("getting tenant resulted in unexpected code: 500"),
		},
	}

	for i := range tcs {
		tc := tcs[i]
		t.Run(fmt.Sprintf("status %v", tc.tadmStatus), func(t *testing.T) {
			t.Parallel()

			var body []byte

			body, err := json.Marshal(tc.tadmBody)
			assert.NoError(t, err)

			s, rd := ct.NewMockServer(tc.tadmStatus, body)

			c := NewClient(Config{
				TenantAdmAddr: s.URL,
			})

			tenant, err := c.GetTenant(context.Background(), tc.tid)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				repl := strings.NewReplacer(":tid", tc.tid)
				uri := repl.Replace(TenantGetUri)
				assert.Equal(t, uri, rd.Url.Path)
				assert.Equal(t, tc.tenant, tenant)
			}
			s.Close()
		})
	}
}

func restError(msg string) interface{} {
	return map[string]interface{}{"error": msg, "request_id": "test"}
}
