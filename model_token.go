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

const (
	TokenStatusActive   = "active"
	TokenStatusExpired  = "expired"
	TokenStatusRejected = "rejected"
)

type Token struct {
	Id     string `json:"id"`
	DevId  string `json:"dev_id"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

func NewToken(id string, dev_id string, token string) *Token {
	return &Token{
		Id:     id,
		DevId:  dev_id,
		Token:  token,
		Status: TokenStatusActive,
	}
}
