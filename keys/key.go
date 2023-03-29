// Copyright 2022 Northern.tech AS
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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

const (
	ErrMsgPrivKeyReadFailed    = "failed to read server private key file"
	ErrMsgPrivKeyNotPEMEncoded = "server private key not PEM-encoded"

	blockTypePKCS1 = "RSA PRIVATE KEY"
	blockTypePKCS8 = "PRIVATE KEY"
)

func LoadRSAPrivate(privKeyPath string) (*rsa.PrivateKey, error) {
	var (
		err     error
		pemData []byte
		rsaKey  *rsa.PrivateKey
	)
	// read key from file
	pemData, err = ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, ErrMsgPrivKeyReadFailed)
	}
	// decode pem key
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, &os.PathError{
			Err:  errors.New(ErrMsgPrivKeyNotPEMEncoded),
			Op:   "PEMDecode",
			Path: privKeyPath,
		}
	}

	switch block.Type {
	case blockTypePKCS1:
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case blockTypePKCS8:
		var (
			key interface{}
			ok  bool
		)
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if rsaKey, ok = key.(*rsa.PrivateKey); !ok || rsaKey == nil {
			err = errors.New("key type not supported")
		}
	default:
		err = errors.Errorf("invalid PEM block header: %s", block.Type)
	}
	if err != nil {
		err = &os.PathError{
			Err:  err,
			Op:   "LoadRSAPrivate",
			Path: privKeyPath,
		}
	}
	return rsaKey, err
}
