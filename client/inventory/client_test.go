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
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientPatchDeviceV2(t *testing.T) {
	cases := map[string]struct {
		did  string
		tid  string
		src  string
		ts   int64
		attr []Attribute

		code int
	}{
		"ok": {
			did: "dev1",
			tid: "tenant",
			src: "deviceauth",
			ts:  12341234,

			attr: []Attribute{
				{
					Name:        "foo",
					Value:       "fooval",
					Description: "foodesc",
					Scope:       "inventory",
				},
				{
					Name:        "bar",
					Value:       "barval",
					Description: "bardesc",
					Scope:       "identity",
				},
			},

			code: http.StatusOK,
		},
		"ok, no tenant": {
			did: "dev1",
			src: "deviceauth",
			ts:  12341234,

			attr: []Attribute{
				{
					Name:        "foo",
					Value:       "fooval",
					Description: "foodesc",
					Scope:       "inventory",
				},
			},

			code: http.StatusOK,
		},
		"error: inventory": {
			did: "dev1",
			src: "deviceauth",
			ts:  12341234,

			attr: []Attribute{
				{
					Name:        "foo",
					Value:       "fooval",
					Description: "foodesc",
					Scope:       "inventory",
				},
			},

			code: http.StatusBadRequest,
		},
	}

	for d := range cases {
		tc := cases[d]
		t.Run(fmt.Sprintf("case: %s", d), func(t *testing.T) {
			t.Parallel()

			s := httptest.NewServer(
				http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(tc.code)
						if tc.code != http.StatusOK {
							return
						}

						assert.Equal(t,
							r.URL.Path,
							"/api/internal/v2/inventory/devices/"+tc.did)
						assert.Equal(t, tc.src, r.Header.Get("X-MEN-Source"))
						assert.Equal(t, strconv.FormatUint(uint64(tc.ts), 10), r.Header.Get("X-MEN-Msg-Timestamp"))

						if tc.tid != "" {
							assert.Equal(t, tc.tid, r.URL.Query().Get("tenant_id"))
						}

						defer r.Body.Close()
						b, err := ioutil.ReadAll(r.Body)

						assert.NoError(t, err)

						var outattr []Attribute
						err = json.Unmarshal(b, &outattr)

						assert.NoError(t, err)
						assert.Equal(t, tc.attr, outattr)

					}))

			c := NewClient(s.URL, true)
			err := c.PatchDeviceV2(context.TODO(),
				tc.did,
				tc.tid,
				tc.src,
				tc.ts,
				tc.attr)

			if tc.code == http.StatusOK {
				assert.NoError(t, err)
			} else {
				s := fmt.Sprintf("PATCH %s request failed with status %d %s", s.URL+"/api/internal/v2/inventory/devices/"+tc.did, tc.code, http.StatusText(tc.code))
				assert.EqualError(t, err, s)
			}
		})
	}
}
