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
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeviceFilterParseForm(t *testing.T) {

	testCases := []struct {
		Name string

		Form url.Values

		Result DeviceFilter
		Error  error
	}{{
		Name: "ok",

		Form: url.Values{
			"status": []string{"pending"},
			"id": []string{
				"66c3a801-c5da-4f23-9ab7-7489127ad473",
				"66c3a801-c5da-4f23-9ab7-7489127ad474",
			},
		},
		Result: DeviceFilter{
			Status: func() *string {
				s := "pending"
				return &s
			}(),
			IDs: []string{
				"66c3a801-c5da-4f23-9ab7-7489127ad473",
				"66c3a801-c5da-4f23-9ab7-7489127ad474",
			},
		},
	}, {
		Name: "error, invalid status",

		Form: url.Values{
			"status": []string{"occupied"},
		},
		Error: errors.New("parameter status must be one of: " +
			"pending, rejected, accepted or preauthorized"),
	}}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			var fltr DeviceFilter

			err := fltr.ParseForm(tc.Form)
			if tc.Error != nil {
				assert.EqualError(t, err, tc.Error.Error())
			} else {
				assert.Equal(t, tc.Result, fltr)
			}
		})
	}
}
