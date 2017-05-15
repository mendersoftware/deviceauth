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
	"github.com/mendersoftware/deviceauth/config"
)

const (
	SettingListen        = "listen"
	SettingListenDefault = ":8080"

	SettingMiddleware        = "middleware"
	SettingMiddlewareDefault = EnvProd

	SettingDb        = "mongo"
	SettingDbDefault = "mongo-device-auth"

	SettingDevAdmAddr        = "devadm_addr"
	SettingDevAdmAddrDefault = "http://mender-device-adm:8080/"

	SettingInventoryAddr        = "inventory_addr"
	SettingInventoryAddrDefault = "http://mender-inventory:8080/"

	SettingOrchestratorAddr        = "device_auth_orchestrator"
	SettingOrchestratorAddrDefault = "http://mender-conductor:8080/"

	SettingTenantAdmAddr        = "tenantadm_addr"
	SettingTenantAdmAddrDefault = ""

	SettingServerPrivKeyPath        = "server_priv_key_path"
	SettingServerPrivKeyPathDefault = "/etc/deviceauth/rsa/private.pem"

	SettingJWTIssuer        = "jwt_issuer"
	SettingJWTIssuerDefault = "Mender"

	SettingJWTExpirationTimeout        = "jwt_exp_timeout"
	SettingJWTExpirationTimeoutDefault = "604800" //one week
)

var (
	configValidators = []config.Validator{}
	configDefaults   = []config.Default{
		{Key: SettingListen, Value: SettingListenDefault},
		{Key: SettingMiddleware, Value: SettingMiddlewareDefault},
		{Key: SettingDb, Value: SettingDbDefault},
		{Key: SettingDevAdmAddr, Value: SettingDevAdmAddrDefault},
		{Key: SettingInventoryAddr, Value: SettingInventoryAddrDefault},
		{Key: SettingOrchestratorAddr, Value: SettingOrchestratorAddrDefault},
		{Key: SettingTenantAdmAddr, Value: SettingTenantAdmAddrDefault},
		{Key: SettingServerPrivKeyPath, Value: SettingServerPrivKeyPathDefault},
		{Key: SettingJWTIssuer, Value: SettingJWTIssuerDefault},
		{Key: SettingJWTExpirationTimeout, Value: SettingJWTExpirationTimeoutDefault},
	}
)
