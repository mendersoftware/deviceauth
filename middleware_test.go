// Copyright 2023 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package main

import (
	"fmt"
	"testing"

	"github.com/ant0ine/go-json-rest/rest"
)

func TestSetupMiddleware(t *testing.T) {

	var tdata = []struct {
		mwtype string
		experr bool
	}{
		{"foo", true},
		{EnvProd, false},
		{EnvDev, false},
	}

	for i, td := range tdata {
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			api := rest.NewApi()

			err := SetupMiddleware(api, td.mwtype)
			if err != nil && td.experr == false {
				t.Errorf("dod not expect error: %s", err)
			} else if err == nil && td.experr == true {
				t.Errorf("expected error, got none")
			}
		})
	}
}
