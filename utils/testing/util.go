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
package testing

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"testing"

	"golang.org/x/crypto/ed25519"
)

const (
	PrivKeyBlockType = "RSA PRIVATE KEY"
)

func AuthReqSign(data []byte, privkey interface{}, t *testing.T) []byte {
	var b64 []byte

	switch privkey := privkey.(type) {
	case *rsa.PrivateKey:
		hash := sha256.New()
		if _, err := bytes.NewReader(data).WriteTo(hash); err != nil {
			t.Fatal(err)
		}

		sig, err := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, hash.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}

		b64 = make([]byte, base64.StdEncoding.EncodedLen(len(sig)))
		base64.StdEncoding.Encode(b64, sig)

	case *ed25519.PrivateKey:
		sig := ed25519.Sign(*privkey, data)

		b64 = make([]byte, base64.StdEncoding.EncodedLen(len(sig)))
		base64.StdEncoding.Encode(b64, sig)

	default:
		t.Fatal(errors.New("unsupported private key type"))
	}

	return b64
}

func LoadPrivKeyX509(path string, t *testing.T) *rsa.PrivateKey {
	pem_data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(pem_data)

	if block == nil ||
		block.Type != PrivKeyBlockType {
		t.Fatal(err)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func LoadPrivKeyEd25519(path string, t *testing.T) *ed25519.PrivateKey {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	priv := ed25519.PrivateKey(data)

	return &priv
}

func LoadPubKeyStrX509(path string, t *testing.T) string {
	pem_data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return string(pem_data)
}

func LoadPubKeyEd25519(path string, t *testing.T) []byte {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
