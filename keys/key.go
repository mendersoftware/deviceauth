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
package keys

import (
	"crypto/ed25519"
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/pkg/errors"
)

const (
	ErrMsgPrivKeyReadFailed = "failed to read server private key file"
)

func LoadRSAPrivate(privKeyPath string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, ErrMsgPrivKeyReadFailed)
	}
	return jwt.ParseRSAPrivateKeyFromPEM(pemData)
}

func LoadEd25519Private(privKeyPath string) (*ed25519.PrivateKey, error) {
	pemData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, ErrMsgPrivKeyReadFailed)
	}
	private, err := jwt.ParseEdPrivateKeyFromPEM(pemData)
	if err != nil {
		return nil, err
	}
	// safe, already asserted by `jwt.ParseEdPrivateKeyFromPEM`
	key := private.(ed25519.PrivateKey)
	return &key, nil
}
