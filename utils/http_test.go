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
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestBuildURL(t *testing.T) {

	hr, _ := http.NewRequest("PUT", "http://1.2.3.4:9999/foo/bar", nil)
	r := &rest.Request{Request: hr}

	u := BuildURL(r, "/api/:id/some/:status/:bar", map[string]string{
		":id":     "1",
		":status": "foo",
	})

	assert.Equal(t, "http://1.2.3.4:9999/api/1/some/foo/:bar", u.String())
}
