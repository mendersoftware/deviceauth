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
package identity

import (
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/stretchr/testify/assert"
)

func TestIdentityMiddlewareNoIdentity(t *testing.T) {
	api := rest.NewApi()

	api.Use(&IdentityMiddleware{})

	api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		ctxIdentity := FromContext(r.Context())
		assert.Empty(t, ctxIdentity)
		w.WriteJson(map[string]string{"foo": "bar"})
	}))

	handler := api.MakeHandler()

	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)

	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}

func TestIdentityMiddlewareNoSubject(t *testing.T) {
	api := rest.NewApi()

	api.Use(&IdentityMiddleware{})

	identity := Identity{
		Tenant: "bar",
	}

	api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		ctxIdentity := FromContext(r.Context())
		assert.Empty(t, ctxIdentity)
		w.WriteJson(map[string]string{"foo": "bar"})
	}))

	handler := api.MakeHandler()

	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	rawclaims := makeClaimsPart(identity.Subject, identity.Tenant)
	req.Header.Set("Authorization", "Bearer foo."+rawclaims+".bar")

	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}

func TestIdentityMiddlewareNoTenant(t *testing.T) {
	api := rest.NewApi()

	api.Use(&IdentityMiddleware{})

	identity := Identity{
		Subject: "foo",
	}

	api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		ctxIdentity := FromContext(r.Context())
		assert.Equal(t, &identity, ctxIdentity)
		w.WriteJson(map[string]string{"foo": "bar"})
	}))

	handler := api.MakeHandler()

	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	rawclaims := makeClaimsPart(identity.Subject, identity.Tenant)
	req.Header.Set("Authorization", "Bearer foo."+rawclaims+".bar")

	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}

func TestIdentityMiddleware(t *testing.T) {
	api := rest.NewApi()

	api.Use(&IdentityMiddleware{})

	identity := Identity{
		Subject: "foo",
		Tenant:  "bar",
	}

	api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
		ctxIdentity := FromContext(r.Context())
		assert.Equal(t, &identity, ctxIdentity)
		w.WriteJson(map[string]string{"foo": "bar"})
	}))

	handler := api.MakeHandler()

	req := test.MakeSimpleRequest("GET", "http://localhost/", nil)
	rawclaims := makeClaimsPart(identity.Subject, identity.Tenant)
	req.Header.Set("Authorization", "Bearer foo."+rawclaims+".bar")

	recorded := test.RunRequest(t, handler, req)
	recorded.CodeIs(200)
	recorded.ContentTypeIsJson()
}
