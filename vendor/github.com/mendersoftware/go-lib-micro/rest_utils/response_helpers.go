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
package rest_utils

import (
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/pkg/errors"

	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestid"
)

// return selected http code + error message directly taken from error
// log error
func RestErrWithLog(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int) {
	RestErrWithLogMsg(w, r, l, e, code, e.Error())
}

// return http 500, with an "internal error" message
// log full error
func RestErrWithLogInternal(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error) {
	msg := "internal error"
	e = errors.Wrap(e, msg)
	RestErrWithLogMsg(w, r, l, e, http.StatusInternalServerError, msg)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error as debug
func RestErrWithDebugMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	restErrWithLogMsg(w, r, l, e, code, msg, logrus.DebugLevel)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error as info
func RestErrWithInfoMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	restErrWithLogMsg(w, r, l, e, code, msg, logrus.InfoLevel)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error as warning
func RestErrWithWarningMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	restErrWithLogMsg(w, r, l, e, code, msg, logrus.WarnLevel)
}

// same as RestErrWithErrorMsg - for backward compatibility purpose
// return an error code with an overriden message (to avoid exposing the details)
// log full error as error
func RestErrWithLogMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	restErrWithLogMsg(w, r, l, e, code, msg, logrus.ErrorLevel)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error as error
func RestErrWithErrorMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	restErrWithLogMsg(w, r, l, e, code, msg, logrus.ErrorLevel)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error as fatal
func RestErrWithFatalMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	restErrWithLogMsg(w, r, l, e, code, msg, logrus.FatalLevel)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error as panic
func RestErrWithPanicMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger, e error, code int, msg string) {
	restErrWithLogMsg(w, r, l, e, code, msg, logrus.PanicLevel)
}

// return an error code with an overriden message (to avoid exposing the details)
// log full error with given log level
func restErrWithLogMsg(w rest.ResponseWriter, r *rest.Request, l *log.Logger,
	e error, code int, msg string, logLevel logrus.Level) {
	w.WriteHeader(code)
	err := w.WriteJson(map[string]string{
		rest.ErrorFieldName: msg,
		"request_id":        requestid.GetReqId(r),
	})
	if err != nil {
		panic(err)
	}
	switch logLevel {
	case logrus.DebugLevel:
		l.F(log.Ctx{}).Debug(errors.Wrap(e, msg).Error())
	case logrus.InfoLevel:
		l.F(log.Ctx{}).Info(errors.Wrap(e, msg).Error())
	case logrus.WarnLevel:
		l.F(log.Ctx{}).Warn(errors.Wrap(e, msg).Error())
	case logrus.ErrorLevel:
		l.F(log.Ctx{}).Error(errors.Wrap(e, msg).Error())
	case logrus.FatalLevel:
		l.F(log.Ctx{}).Fatal(errors.Wrap(e, msg).Error())
	case logrus.PanicLevel:
		l.F(log.Ctx{}).Panic(errors.Wrap(e, msg).Error())
	}
}
