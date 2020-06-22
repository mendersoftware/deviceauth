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
package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestClientPatchDeviceV2(t *testing.T) {
	cases := map[string]struct {
		did  string
		tid  string
		src  string
		ts   int64
		attr []Attribute

		doNotStartServer bool
		code             int
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
		"error: connection refused": {
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

			doNotStartServer: true,
		},
	}

	for d := range cases {
		tc := cases[d]
		t.Run(fmt.Sprintf("case: %s", d), func(t *testing.T) {
			t.Parallel()

			if tc.doNotStartServer {
				c := NewClient("http://this.does.not.exists/url/also/", true)
				err := c.PatchDeviceV2(context.TODO(),
					tc.did,
					tc.tid,
					tc.src,
					tc.ts,
					tc.attr)
				assert.True(t, strings.HasPrefix(err.Error(), "failed to submit PATCH"))
				return
			}

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

func TestClientSetDeviceStatus(t *testing.T) {
	cases := map[string]struct {
		tid    string
		did    []string
		status string

		code             int
		errCheckPrefix   bool
		doNotStartServer bool
		err              error
	}{
		"ok": {
			did:    []string{"dev1", "dev2", "dev3"},
			tid:    "tenant",
			status: "accepted",

			code: http.StatusOK,
		},
		"ok, no tenant": {
			did:    []string{"dev1", "dev2", "dev3"},
			status: "accepted",

			code: http.StatusOK,
		},
		"error: inventory": {
			did:    []string{"dev1", "dev2", "dev3"},
			status: "accepted",

			code: http.StatusBadRequest,
		},
		"error: no devices to update": {
			status: "accepted",

			err: errors.New("no devices to update"),
		},
		"error: not a valid url": {
			did:    []string{"dev1", "dev2", "dev3"},
			status: "accepted",
			tid:    "/well, leads to % no / good url/",

			errCheckPrefix: true,
			err:            errors.New("failed to create request: parse"),
		},
		"error: connection refused": {
			did:    []string{"dev1", "dev2", "dev3"},
			status: "accepted",
			tid:    "tenant",

			doNotStartServer: true,
			errCheckPrefix:   true,
			err:              errors.New("failed to create request: parse"),
		},
	}

	for d := range cases {
		tc := cases[d]
		t.Run(fmt.Sprintf("case: %s", d), func(t *testing.T) {
			t.Parallel()

			if tc.doNotStartServer {
				c := NewClient("http://this.does.not.exists/url/also/", true)
				err := c.SetDeviceStatus(context.TODO(),
					tc.tid,
					tc.did,
					tc.status)
				assert.True(t, strings.HasPrefix(err.Error(), "failed to submit POST"))
				return
			}
			s := httptest.NewServer(
				http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(tc.code)
						if tc.code != http.StatusOK {
							return
						}

						url := urlUpdateDeviceStatus + tc.status
						url = strings.Replace(url, ":tid", tc.tid, 1)
						assert.Equal(t,
							r.URL.Path,
							url)
						assert.Equal(t, "deviceauth", r.Header.Get("X-MEN-Source"))

						defer r.Body.Close()
						_, err := ioutil.ReadAll(r.Body)
						assert.NoError(t, err)
					}))

			c := NewClient(s.URL, true)
			err := c.SetDeviceStatus(context.TODO(),
				tc.tid,
				tc.did,
				tc.status)
			if tc.err == nil {
				if tc.code == 0 {
					if tc.errCheckPrefix {
						assert.True(t, strings.HasPrefix(err.Error(), tc.err.Error()))
					} else {
						assert.NoError(t, err)
					}
				}
			} else {
				if tc.errCheckPrefix {
					assert.True(t, strings.HasPrefix(err.Error(), tc.err.Error()))
				} else {
					assert.EqualError(t, err, tc.err.Error())
				}
				return
			}

			if tc.code == http.StatusOK {
				assert.NoError(t, err)
			} else {
				url := urlUpdateDeviceStatus + tc.status
				url = strings.Replace(url, ":tid", tc.tid, 1)
				s := fmt.Sprintf("POST %s request failed with status %d %s", s.URL+url, tc.code, http.StatusText(tc.code))
				assert.EqualError(t, err, s)
			}
		})
	}
}

func TestClientSetDeviceIdentity(t *testing.T) {
	cases := map[string]struct {
		tid     string
		did     string
		didData map[string]interface{}

		code             int
		errCheckPrefix   bool
		doNotStartServer bool
		err              error
	}{
		"ok": {
			did: "dsfgr32r23-dfgst34gsdf-34gs-sdgf34",
			didData: map[string]interface{}{
				"serial":   "vcsdfgsadt7678dfswr543",
				"eMMC-CID": "d0 27 01 32 0f 59 03 ff f6 db ff ef 8a 40 40 00",
				"CPUID":    "0x8000 0008",
			},
			tid: "tenant",

			code: http.StatusOK,
		},
		"ok, no tenant": {
			did: "dsfgr32r23-dfgst34gsdf-34gs-sdgf34",
			didData: map[string]interface{}{
				"serial":   "vcsdfgsadt7678dfswr543",
				"eMMC-CID": "d0 27 01 32 0f 59 03 ff f6 db ff ef 8a 40 40 00",
				"CPUID":    "0x8000 0008",
			},

			code: http.StatusOK,
		},
		"error: inventory": {
			did: "dsfgr32r23-dfgst34gsdf-34gs-sdgf34",
			didData: map[string]interface{}{
				"serial":   "vcsdfgsadt7678dfswr543",
				"eMMC-CID": "d0 27 01 32 0f 59 03 ff f6 db ff ef 8a 40 40 00",
				"CPUID":    "0x8000 0008",
			},

			code: http.StatusBadRequest,
		},
		"error: status attribute is reserved": {
			did: "dsfgr32r23-dfgst34gsdf-34gs-sdgf34",
			didData: map[string]interface{}{
				"status": "accepted",
			},

			err: errors.New("no attributes to update"),
		},
		"error: no device id": {

			err: errors.New("device id is needed"),
		},
		"error: no attributes": {
			did: "dsfgr32r23-dfgst34gsdf-34gs-sdgf34",

			err: errors.New("no attributes to update"),
		},
		"error: not a valid url": {
			did: "dsfgr32r23-dfgst34gsdf-34gs-sdgf34",
			didData: map[string]interface{}{
				"serial":   "vcsdfgsadt7678dfswr543",
				"eMMC-CID": "d0 27 01 32 0f 59 03 ff f6 db ff ef 8a 40 40 00",
				"CPUID":    "0x8000 0008",
			},
			tid: "/well, leads to % no / good url/",

			errCheckPrefix: true,
			err:            errors.New("failed to create request: parse"),
		},
		"error: connection refused": {
			did: "dsfgr32r23-dfgst34gsdf-34gs-sdgf34",
			didData: map[string]interface{}{
				"serial":   "vcsdfgsadt7678dfswr543",
				"eMMC-CID": "d0 27 01 32 0f 59 03 ff f6 db ff ef 8a 40 40 00",
				"CPUID":    "0x8000 0008",
			},
			tid: "tenant",

			doNotStartServer: true,
			errCheckPrefix:   true,
			err:              errors.New("failed to create request: parse"),
		},
	}

	for d := range cases {
		tc := cases[d]
		t.Run(fmt.Sprintf("case: %s", d), func(t *testing.T) {
			t.Parallel()

			if tc.doNotStartServer {
				c := NewClient("http://this.does.not.exists/url/also/", true)
				err := c.SetDeviceIdentity(context.TODO(),
					tc.tid,
					tc.did,
					tc.didData)
				assert.True(t, strings.HasPrefix(err.Error(), "failed to submit PATCH"))
				return
			}
			s := httptest.NewServer(
				http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(tc.code)
						if tc.code != http.StatusOK {
							return
						}

						url := urlSetDeviceAttribute
						url = strings.Replace(url, ":tid", tc.tid, 1)
						url = strings.Replace(url, ":did", tc.did, 1)
						url = strings.Replace(url, ":scope", "identity", 1)
						assert.Equal(t,
							r.URL.Path,
							url)
						assert.Equal(t, "deviceauth", r.Header.Get("X-MEN-Source"))

						defer r.Body.Close()
						_, err := ioutil.ReadAll(r.Body)
						assert.NoError(t, err)
					}))

			c := NewClient(s.URL, true)
			err := c.SetDeviceIdentity(context.TODO(),
				tc.tid,
				tc.did,
				tc.didData)
			if tc.err == nil {
				if tc.code == 0 {
					if tc.errCheckPrefix {
						assert.True(t, strings.HasPrefix(err.Error(), tc.err.Error()))
					} else {
						assert.NoError(t, err)
					}
				}
			} else {
				if tc.errCheckPrefix {
					assert.True(t, strings.HasPrefix(err.Error(), tc.err.Error()))
				} else {
					assert.EqualError(t, err, tc.err.Error())
				}
				return
			}

			if tc.code == http.StatusOK {
				assert.NoError(t, err)
			} else {
				url := urlSetDeviceAttribute
				url = strings.Replace(url, ":tid", tc.tid, 1)
				url = strings.Replace(url, ":did", tc.did, 1)
				url = strings.Replace(url, ":scope", "identity", 1)
				s := fmt.Sprintf("PATCH %s request failed with status %d %s", s.URL+url, tc.code, http.StatusText(tc.code))
				assert.EqualError(t, err, s)
			}
		})
	}
}
