package admin

import (
	"encoding/json"
)

const (
	CodeOk = 400

	CodeErrInvalidAuth   = 401
	ReasonErrInvalidAuth = "Authentication failed"
)

// ApiResponse is the response format for the admin API
type ApiResponse struct {
	Ok     bool        `json:"ok"`
	Code   int         `json:"code"`
	Reason string      `json:"reason"`
	Data   interface{} `json:"data"`
}

// Set sets the data for a successful response
func (e *ApiResponse) Set(data interface{}) *ApiResponse {
	e.Data = data
	e.Code = CodeOk
	e.Ok = true
	return e
}

// SetError sets the error code and reason for a failed response
func (e *ApiResponse) SetError(code int, reason string) *ApiResponse {
	e.Code = code
	e.Reason = reason
	e.Ok = false
	return e
}

// MustMarshall marshalls the response and panics if it fails
func (e *ApiResponse) MustMarshall() []byte {
	data, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}

	return data
}
