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
package main

import (
	"github.com/mendersoftware/go-lib-micro/log"
)

type MockJWTAgent struct {
	mockGenerateTokenSignRS256 func(devId string) (*Token, error)
	mockValidateTokenSignRS256 func(token string) (string, error)
}

func (jwt *MockJWTAgent) GenerateTokenSignRS256(devId string) (*Token, error) {
	return jwt.mockGenerateTokenSignRS256(devId)
}

func (jwt *MockJWTAgent) ValidateTokenSignRS256(token string) (string, error) {
	return jwt.mockValidateTokenSignRS256(token)
}

func (db *MockJWTAgent) UseLog(l *log.Logger) {
	//nop
}
