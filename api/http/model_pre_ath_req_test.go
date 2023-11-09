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
package http

import (
	"encoding/json"
	"fmt"
	mtest "github.com/mendersoftware/deviceauth/utils/testing"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePreAuthReqs(t *testing.T) {
	t.Parallel()

	pubkeyStr := mtest.LoadPubKeyStr("testdata/public.pem")

	testCases := map[string]struct {
		input interface{}
	}{
		"ok": {
			input: []preAuthReq{
				{
					IdData: map[string]interface{}{
						"sn": "0001",
					},
					PubKey: pubkeyStr,
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {
			data, _ := json.Marshal(tc.input)
			req, err := parsePreAuthReqs(strings.NewReader(string(data)))
			assert.NoError(t, err)
			assert.Equal(t, tc.input, req)
		})
	}
}

func TestParsePreAuthReq(t *testing.T) {
	t.Parallel()

	pubkeyStr := mtest.LoadPubKeyStr("testdata/public.pem")

	testCases := map[string]struct {
		input interface{}
	}{
		"ok": {
			input: &preAuthReq{
				IdData: map[string]interface{}{
					"sn": "0001",
				},
				PubKey: pubkeyStr,
			},
		},
	}
	for name, tc := range testCases {
		t.Run(fmt.Sprintf("tc %s", name), func(t *testing.T) {
			data, _ := json.Marshal(tc.input)
			req, err := parsePreAuthReq(strings.NewReader(string(data)))
			assert.NoError(t, err)
			assert.Equal(t, tc.input, req)
		})
	}
}
