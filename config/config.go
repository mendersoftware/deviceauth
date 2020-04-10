// Copyright 2020 Northern.tech AS
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
package config

import (
	"github.com/mendersoftware/go-lib-micro/config"
)

const (
	SettingListen        = "listen"
	SettingListenDefault = ":8080"

	SettingMiddleware        = "middleware"
	SettingMiddlewareDefault = "prod"

	SettingDb        = "mongo"
	SettingDbDefault = "mongo-device-auth"

	SettingDbSSL        = "mongo_ssl"
	SettingDbSSLDefault = false

	SettingDbSSLSkipVerify        = "mongo_ssl_skipverify"
	SettingDbSSLSkipVerifyDefault = false

	SettingDbUsername = "mongo_username"
	SettingDbPassword = "mongo_password"

	SettingDevAdmAddr        = "devadm_addr"
	SettingDevAdmAddrDefault = "http://mender-device-adm:8080/"

	SettingInventoryAddr        = "inventory_addr"
	SettingInventoryAddrDefault = "http://mender-inventory:8080/"

	SettingOrchestratorAddr        = "orchestrator_addr"
	SettingOrchestratorAddrDefault = "http://mender-workflows-server:8080/"

	SettingTenantAdmAddr        = "tenantadm_addr"
	SettingTenantAdmAddrDefault = ""

	SettingDefaultTenantToken        = "default_tenant_token"
	SettingDefaultTenantTokenDefault = ""

	SettingServerPrivKeyPath        = "server_priv_key_path"
	SettingServerPrivKeyPathDefault = "/etc/deviceauth/rsa/private.pem"

	SettingJWTIssuer        = "jwt_issuer"
	SettingJWTIssuerDefault = "Mender"

	SettingJWTExpirationTimeout        = "jwt_exp_timeout"
	SettingJWTExpirationTimeoutDefault = "604800" //one week

	SettingMaxDevicesLimitDefault        = "max_devices_limit_default"
	SettingMaxDevicesLimitDefaultDefault = "0" // no limit

	SettingRedisAddress        = "redis_address"
	SettingRedisAddressDefault = ""

	SettingRedisPassword        = "redis_password"
	SettingRedisPasswordDefault = ""

	SettingRedisDb        = "redis_db"
	SettingRedisDbDefault = "0"
)

var (
	Validators = []config.Validator{}
	Defaults   = []config.Default{
		{Key: SettingListen, Value: SettingListenDefault},
		{Key: SettingMiddleware, Value: SettingMiddlewareDefault},
		{Key: SettingDb, Value: SettingDbDefault},
		{Key: SettingDevAdmAddr, Value: SettingDevAdmAddrDefault},
		{Key: SettingInventoryAddr, Value: SettingInventoryAddrDefault},
		{Key: SettingOrchestratorAddr, Value: SettingOrchestratorAddrDefault},
		{Key: SettingTenantAdmAddr, Value: SettingTenantAdmAddrDefault},
		{Key: SettingDefaultTenantToken, Value: SettingDefaultTenantTokenDefault},
		{Key: SettingServerPrivKeyPath, Value: SettingServerPrivKeyPathDefault},
		{Key: SettingJWTIssuer, Value: SettingJWTIssuerDefault},
		{Key: SettingJWTExpirationTimeout, Value: SettingJWTExpirationTimeoutDefault},
		{Key: SettingDbSSL, Value: SettingDbSSLDefault},
		{Key: SettingDbSSLSkipVerify, Value: SettingDbSSLSkipVerifyDefault},
		{Key: SettingMaxDevicesLimitDefault, Value: SettingMaxDevicesLimitDefaultDefault},
		{Key: SettingRedisAddress, Value: SettingRedisAddressDefault},
		{Key: SettingRedisPassword, Value: SettingRedisPasswordDefault},
		{Key: SettingRedisDb, Value: SettingRedisDbDefault},
	}
)
