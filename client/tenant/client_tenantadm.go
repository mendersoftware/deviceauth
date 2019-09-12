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
package tenant

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/mendersoftware/go-lib-micro/apiclient"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/pkg/errors"

	"github.com/mendersoftware/deviceauth/utils"
)

const (
	// devices endpoint
	TenantVerifyUri = "/api/internal/v1/tenantadm/tenants/verify"
	// default request timeout, 10s?
	defaultReqTimeout = time.Duration(10) * time.Second
)

const (
	MsgErrTokenVerificationFailed = "tenant token verification failed"
	MsgErrTokenMissing            = "tenant token missing"
)

func IsErrTokenVerificationFailed(e error) bool {
	return strings.HasPrefix(e.Error(), MsgErrTokenVerificationFailed)
}

func MakeErrTokenVerificationFailed(apiErr error) error {
	return errors.Wrap(apiErr, MsgErrTokenVerificationFailed)
}

func IsErrTokenMissing(e error) bool {
	return strings.HasPrefix(e.Error(), MsgErrTokenMissing)
}

// ClientConfig conveys client configuration
type Config struct {
	// Tenant administrator service address
	TenantAdmAddr string
	// Request timeout
	Timeout time.Duration
}

// ClientRunner is an interface of inventory client
type ClientRunner interface {
	VerifyToken(ctx context.Context, token string, client apiclient.HttpRunner) error
}

// Client is an opaque implementation of tenant administrator client. Implements
// ClientRunner interface
type Client struct {
	conf Config
}

// VerifyToken will execute a request to tenenatadm's endpoint for token
// verification. Returns nil if verification was successful.
func (tc *Client) VerifyToken(ctx context.Context, token string,
	client apiclient.HttpRunner) error {

	l := log.FromContext(ctx)

	// TODO sanitize token

	url := utils.JoinURL(tc.conf.TenantAdmAddr, TenantVerifyUri)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create request to tenant administrator")
	}

	// tenant token is passed in Authorization header
	req.Header.Add("Authorization", "Bearer "+token)

	ctx, cancel := context.WithTimeout(ctx, tc.conf.Timeout)
	defer cancel()

	rsp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		l.Errorf("tenantadm request failed: %v", err)
		return errors.Wrap(err, "request to verify token failed")
	}
	defer rsp.Body.Close()

	switch rsp.StatusCode {

	case http.StatusUnauthorized: // 401, verification result negative
		apiErr := rest_utils.ParseApiError(rsp.Body)
		if !rest_utils.IsApiError(apiErr) {
			return errors.Errorf("failed to parse tenantadm api error response")
		}

		return MakeErrTokenVerificationFailed(apiErr)

	case http.StatusOK: // 200, token verified
		return nil
	default:
		return errors.Errorf("token verification request returned unexpected status %v",
			rsp.StatusCode)
	}
}

// NewClient creates a client with given config.
func NewClient(c Config) *Client {
	if c.Timeout == 0 {
		c.Timeout = defaultReqTimeout
	}

	return &Client{
		conf: c,
	}
}
