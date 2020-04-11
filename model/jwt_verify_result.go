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

package model

import (
	"time"
)

// JWTVerifyResult holds the result of the JWT token verification
type JWTVerifyResult struct {
	DeviceID                string        `json:"-"`
	Expiration              time.Duration `json:"-"`
	Expired                 bool          `json:"expired"`
	Valid                   bool          `json:"valid"`
	LatestDeploymentsNext   time.Time     `json:"latest_deployments_next"`
	IntervalDeploymentsNext time.Duration `json:"interval_deployments_next"`
	LatestInventoryUpdate   time.Time     `json:"latest_inventory_update"`
	IntervalInventoryUpdate time.Duration `json:"interval_inventory_update"`
}
