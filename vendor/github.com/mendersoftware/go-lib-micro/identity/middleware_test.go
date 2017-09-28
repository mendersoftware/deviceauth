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
package identity

import (
	"fmt"
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
	"github.com/ant0ine/go-json-rest/rest/test"
	"github.com/stretchr/testify/assert"

	"github.com/mendersoftware/go-lib-micro/log"
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

func TestIdentityMiddlewareDevice(t *testing.T) {
	testCases := []struct {
		identity  Identity
		mw        *IdentityMiddleware
		logFields map[string]interface{}
	}{
		{
			identity: Identity{
				Subject:  "device-1",
				Tenant:   "bar",
				IsDevice: true,
			},
			mw: &IdentityMiddleware{
				UpdateLogger: true,
			},
			logFields: map[string]interface{}{
				"device_id": "device-1",
				"tenant_id": "bar",
			},
		},
		{
			identity: Identity{
				Subject: "user-1",
				Tenant:  "bar",
				IsUser:  true,
			},
			mw: &IdentityMiddleware{
				UpdateLogger: true,
			},
			logFields: map[string]interface{}{
				"user_id":   "user-1",
				"tenant_id": "bar",
			},
		},
		{
			identity: Identity{
				Subject: "not-a-user-not-a-device",
				Tenant:  "bar",
			},
			mw: &IdentityMiddleware{
				UpdateLogger: true,
			},
			logFields: map[string]interface{}{
				"sub":       "not-a-user-not-a-device",
				"tenant_id": "bar",
			},
		},
		{
			identity: Identity{
				Subject:  "123-dobby-has-no-master",
				IsDevice: true,
			},
			mw: &IdentityMiddleware{
				UpdateLogger: true,
			},
			logFields: map[string]interface{}{
				"device_id": "123-dobby-has-no-master",
				"tenant_id": nil,
			},
		},
	}

	for idx := range testCases {
		tc := testCases[idx]
		t.Run(fmt.Sprintf("tc %d", idx), func(t *testing.T) {
			api := rest.NewApi()

			api.Use(tc.mw)

			api.SetApp(rest.AppSimple(func(w rest.ResponseWriter, r *rest.Request) {
				ctxIdentity := FromContext(r.Context())

				assert.Equal(t, &tc.identity, ctxIdentity)

				l := log.FromContext(r.Context())
				l.Infof("foobar")
				for f, v := range tc.logFields {
					assert.Equal(t, v, l.Data[f])
				}
				w.WriteJson(map[string]string{"foo": "bar"})
			}))

			handler := api.MakeHandler()

			req := test.MakeSimpleRequest("GET", "http://localhost/", nil)

			claims := makeClaimsFull(tc.identity.Subject, tc.identity.Tenant,
				tc.identity.IsDevice, tc.identity.IsUser)
			req.Header.Set("Authorization", "Bearer foo."+claims+".bar")

			recorded := test.RunRequest(t, handler, req)
			recorded.CodeIs(200)
			recorded.ContentTypeIsJson()
		})
	}
}
