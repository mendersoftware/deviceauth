// Copyright 2018 Northern.tech AS
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
	"context"
	"io/ioutil"
	"strings"

	"github.com/ant0ine/go-json-rest/rest"
)

const (
	ctxKeyForwardedForIp = "X-Forwarded-For"
)

func GetForwardedFor(ctx context.Context) string {
	res, _ := ctx.Value(ctxKeyForwardedForIp).(string)
	return res
}

func SaveForwardedFor(ctx context.Context, value string) context.Context {
	return context.WithValue(ctx, ctxKeyForwardedForIp, value)
}

func ReadBodyRaw(r *rest.Request) ([]byte, error) {
	content, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}

	return content, nil
}

func JoinURL(base, url string) string {
	if strings.HasPrefix(url, "/") {
		url = url[1:]
	}
	if !strings.HasSuffix(base, "/") {
		base = base + "/"
	}
	return base + url

}
