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
package requestid

import (
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
)

func TestRequestIdMiddlewareWithReqID(t *testing.T) {
	api := rest.NewApi()

	api.Use(&RequestIdMiddleware{})

	reqid := "4420a5b9-dbf2-4e5d-8b4f-3cf2013d04af"
	api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		assert.Equal(t, reqid, FromContext(r.Context()))
		w.WriteJson(map[string]string{"foo": "bar"})
	}))

	handler := api.MakeHandler()

	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	req.Header.Set(RequestIdHeader, reqid)

	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
	recorded.HeaderIs(RequestIdHeader, reqid)

}

func TestRequestIdMiddlewareNoReqID(t *testing.T) {
	api := rest.NewApi()

	api.Use(&RequestIdMiddleware{})

	api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		reqid := FromContext(r.Context())
		_, err := uuid.FromString(reqid)
		assert.NoError(t, err)
		w.WriteJson(map[string]string{"foo": "bar"})
	}))

	handler := api.MakeHandler()

	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
	outReqIdStr := recorded.Recorder.HeaderMap.Get(RequestIdHeader)
	_, err := uuid.FromString(outReqIdStr)
	assert.NoError(t, err)
}
