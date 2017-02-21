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
package utils

import (
	"crypto/rsa"
	"testing"

	"github.com/mendersoftware/deviceauth/test"
	"github.com/stretchr/testify/assert"
)

func TestVerifyAuthReqSign(t *testing.T) {

	testCases := []struct {
		content   string
		pubkeyStr string
		privkey   *rsa.PrivateKey
		err       string
	}{
		{
			//correctly signed, matching keypair
			`{
				"id_data": {"mac": "deadbeef"},
				"tenant_token": "token"
				"seq_no": 1
			}`,
			test.LoadPubKeyStr("../testdata/public.pem", t),
			test.LoadPrivKey("../testdata/private.pem", t),
			"",
		},
		{
			//mismatched keypair
			`{
				"id_data": {"mac": "deadbeef"},
				"tenant_token": "token"
				"seq_no": 1
			}`,
			test.LoadPubKeyStr("../testdata/public.pem", t),
			test.LoadPrivKey("../testdata/private_invalid.pem", t),
			"verification failed: crypto/rsa: verification error",
		},
		{
			//invalid public key
			`{
				"id_data": {"mac": "deadbeef"},
				"tenant_token": "token"
				"seq_no": 1
			}`,
			"invalidpubkey",
			test.LoadPrivKey("../testdata/private.pem", t),
			ErrMsgVerify,
		},
	}

	for _, tc := range testCases {
		signed := test.AuthReqSign([]byte(tc.content), tc.privkey, t)

		err := VerifyAuthReqSign(string(signed),
			tc.pubkeyStr,
			[]byte(tc.content))

		if tc.err != "" {
			assert.EqualError(t, err, tc.err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestVerifyCreateDevId(t *testing.T) {
	iddata := `{"mac":"00:00:00:01", "id" : "id-1"}`
	id := CreateDevId(iddata)
	assert.Equal(t, "b8f8981a80d1f214766a43f5cb3db24e12b9ef04c62a30fb77aec6f70b229e12", id)
}
