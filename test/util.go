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
package test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

const (
	PrivKeyBlockType = "RSA PRIVATE KEY"
)

func AuthReqSign(data []byte, privkey *rsa.PrivateKey, t *testing.T) []byte {
	hash := sha256.New()
	if _, err := bytes.NewReader(data).WriteTo(hash); err != nil {
		t.FailNow()
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, privkey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		t.FailNow()
	}

	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(sig)))
	base64.StdEncoding.Encode(b64, sig)

	return b64
}

func LoadPrivKey(path string, t *testing.T) *rsa.PrivateKey {
	pem_data, err := ioutil.ReadFile(path)
	if err != nil {
		t.FailNow()
	}

	block, _ := pem.Decode(pem_data)

	if block == nil ||
		block.Type != PrivKeyBlockType {
		t.FailNow()
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.FailNow()
	}

	return key
}

func LoadPubKeyStr(path string, t *testing.T) string {
	pem_data, err := ioutil.ReadFile(path)
	if err != nil {
		t.FailNow()
	}

	return string(pem_data)
}
