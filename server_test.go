// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package main

import (
	"testing"

	"github.com/mendersoftware/deviceauth/config"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestSetupApi(t *testing.T) {
	// expecting an error
	api, err := SetupAPI("foo")
	assert.Nil(t, api)
	assert.Error(t, err)

	api, err = SetupAPI(EnvDev)
	assert.NotNil(t, api)
	assert.Nil(t, err)
}

func TestGetJWTHandler(t *testing.T) {
	testCases := map[string]struct {
		privateKeyType         string
		privateKeyPath         string
		fallbackPrivateKeyPath string
		err                    error
	}{
		"ok, rsa": {
			privateKeyType: config.SettingServerPrivKeyTypeRSA,
			privateKeyPath: "jwt/testdata/rsa.pem",
		},
		"ko, rsa": {
			privateKeyType: config.SettingServerPrivKeyTypeRSA,
			privateKeyPath: "jwt/testdata/doesnotexist.pem",
			err:            errors.New("failed to read rsa private key: failed to read server private key file: open jwt/testdata/doesnotexist.pem: no such file or directory"),
		},
		"ok, ed25519": {
			privateKeyType: config.SettingServerPrivKeyTypeEd25519,
			privateKeyPath: "jwt/testdata/ed25519.pem",
		},
		"ko, ed25519": {
			privateKeyType: config.SettingServerPrivKeyTypeEd25519,
			privateKeyPath: "jwt/testdata/doesnotexist.pem",
			err:            errors.New("failed to read ed25519 private key: failed to read server private key file: open jwt/testdata/doesnotexist.pem: no such file or directory"),
		},
		"unknown priate key type": {
			privateKeyType: "dummy",
			err:            errors.New("unsupported server private key type dummy"),
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			_, err := getJWTHandler(tc.privateKeyType, tc.privateKeyPath)
			if tc.err != nil {
				assert.EqualError(t, err, tc.err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
