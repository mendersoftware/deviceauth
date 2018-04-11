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
package tenant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	ct "github.com/mendersoftware/deviceauth/client/testing"
)

func TestClientGet(t *testing.T) {
	t.Parallel()

	c := NewClient(Config{TenantAdmAddr: "http://foo"})
	assert.NotNil(t, c)
}

func TestClient(t *testing.T) {
	t.Parallel()

	tcs := []struct {
		status int
		body   []byte
		token  string
		err    error
	}{
		{
			status: http.StatusBadRequest,
			err:    errors.New("token verification request returned unexpected status 400"),
		},
		{
			// try some bogus status
			status: http.StatusNotAcceptable,
			err:    errors.New("token verification request returned unexpected status 406"),
		},
		{
			// token verified ok
			status: http.StatusOK,
		},
		{
			status: http.StatusUnauthorized,
			body:   restError("account suspended"),
			err:    errors.New("token verification failed: account suspended"),
		},
	}

	for i := range tcs {
		tc := tcs[i]
		t.Run(fmt.Sprintf("status %v", tc.status), func(t *testing.T) {
			t.Parallel()

			s, rd := ct.NewMockServer(tc.status, tc.body)

			c := NewClient(Config{
				TenantAdmAddr: s.URL,
			})

			err := c.VerifyToken(context.Background(), tc.token, &apiclient.HttpApi{})
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, TenantVerifyUri, rd.Url.Path)
			}
			s.Close()
		})
	}
}

func restError(msg string) []byte {
	err, _ := json.Marshal(map[string]interface{}{"error": msg, "request_id": "test"})
	return err
}
