// Copyright 2017 Northern.tech AS
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
package model

type Token struct {
	Id        string `json:"id" bson:"_id"`
	DevId     string `json:"dev_id" bson:"dev_id,omitempty"`
	AuthSetId string `json:"auth_id" bson:"auth_id,omitempty"`
	Token     string `json:"token" bson:"token,omitempty"`
}

func NewToken(id string, dev_id string, token string) *Token {
	return &Token{
		Id:    id,
		DevId: dev_id,
		Token: token,
	}
}

func (t *Token) WithAuthSet(set *AuthSet) *Token {
	t.AuthSetId = set.Id
	return t
}
