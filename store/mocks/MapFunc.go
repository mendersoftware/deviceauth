// Code generated by mockery v2.10.6. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MapFunc is an autogenerated mock type for the MapFunc type
type MapFunc struct {
	mock.Mock
}

// Execute provides a mock function with given fields: dbCtx
func (_m *MapFunc) Execute(dbCtx context.Context) error {
	ret := _m.Called(dbCtx)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context) error); ok {
		r0 = rf(dbCtx)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
