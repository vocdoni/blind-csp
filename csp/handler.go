package csp

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/arnaucube/go-blindsecp256k1"
	"github.com/vocdoni/blind-csp/handlers"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/bearerstdapi"
)

const (
	processIDSize = 32
)

func (csp *BlindCSP) registerHandlers() error {
	if err := csp.api.RegisterMethod(
		"/ping",
		"GET",
		bearerstdapi.MethodAccessTypePublic,
		csp.ping,
	); err != nil {
		return err
	}

	if err := csp.api.RegisterMethod(
		"/info",
		"GET",
		bearerstdapi.MethodAccessTypePublic,
		csp.info,
	); err != nil {
		return err
	}

	if err := csp.api.RegisterMethod(
		"/{processId}/{signType}/auth/{step}",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.signatureReq,
	); err != nil {
		return err
	}

	if err := csp.api.RegisterMethod(
		"/{processId}/{signType}/auth",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.signatureReq,
	); err != nil {
		return err
	}

	if err := csp.api.RegisterMethod(
		"/{processId}/{signType}/sign",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.signature,
	); err != nil {
		return err
	}

	if err := csp.api.RegisterMethod(
		"/{processId}/sharedkey/{step}",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.sharedKeyReq,
	); err != nil {
		return err
	}

	return csp.api.RegisterMethod(
		"/{processId}/sharedkey",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.sharedKeyReq,
	)
}

// https://server/v1/auth/processes/<processId>/<signType>/auth/<step>

// signatureReq is the signature request handler.
// It executes the AuthCallback function to allow or deny the request to the client.
func (csp *BlindCSP) signatureReq(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	req := &types.Message{}
	if err := req.Unmarshal(msg.Data); err != nil {
		return err
	}

	// Process ID
	var pid types.HexBytes
	if err := pid.UnmarshalBinary([]byte(ctx.URLParam("processId"))); err != nil {
		return fmt.Errorf("cannot decode processId: %w", err)
	}
	if len(pid) != processIDSize {
		return fmt.Errorf("wrong process id: %x", pid)
	}

	// Auth Step
	step, err := strconv.Atoi(ctx.URLParam("step"))
	if err != nil {
		step = 0 // For backwards compability
	}

	// Signature type and auth callback
	var authResp handlers.AuthResponse
	var resp types.Message
	signType := ctx.URLParam("signType")
	if authResp = csp.AuthCallback(ctx.Request, req, pid, signType, step); authResp.Success {
		switch signType {
		case types.SignatureTypeBlind:
			if authResp.AuthToken == nil {
				r, err := csp.NewBlindRequestKey()
				if err != nil {
					return err
				}
				resp.TokenR = r.BytesUncompressed() // use Uncompressed for blindsecp256k1-js compatibility
			}
		case types.SignatureTypeEthereum:
			if authResp.AuthToken == nil {
				resp.TokenR = csp.NewRequestKey()
			}
		default:
			return fmt.Errorf("invalid signature type")
		}
	} else {
		return fmt.Errorf("unauthorized: %s", authResp.String())
	}
	resp.Response = authResp.Response
	resp.AuthToken = authResp.AuthToken
	return ctx.Send(resp.Marshal(), bearerstdapi.HTTPstatusCodeOK)
}

// https://server/v1/auth/processes/<processId>/<signType>/sign

// signature is the performing signature handler.
// If the token is valid and exist in cache, will perform a signature over the Hash
func (csp *BlindCSP) signature(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	req := &types.Message{}
	if err := req.Unmarshal(msg.Data); err != nil {
		return err
	}
	if req.TokenR == nil {
		return fmt.Errorf("token is empty")
	}
	if len(req.Payload) == 0 {
		return fmt.Errorf("message is empty")
	}
	pid, err := hex.DecodeString(trimHex(ctx.URLParam("processId")))
	if err != nil {
		return fmt.Errorf("cannot decode processId: %w", err)
	}
	if len(pid) != processIDSize {
		return fmt.Errorf("wrong process id: %x", pid)
	}

	resp := types.Message{}
	switch ctx.URLParam("signType") {
	case types.SignatureTypeBlind:
		// use Uncompressed for blindsecp256k1-js compatibility
		r, err := blindsecp256k1.NewPointFromBytesUncompressed(req.TokenR)
		if err != nil {
			return err
		}
		resp.Signature, err = csp.SignBlind(r, req.Payload, pid)
		if err != nil {
			return err
		}
	case types.SignatureTypeEthereum:
		var err error
		resp.Signature, err = csp.SignECDSA(req.TokenR, req.Payload, pid)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid signature type")
	}
	return ctx.Send(resp.Marshal(), bearerstdapi.HTTPstatusCodeOK)
}

// https://server/v1/auth/processes/<processId>/sharedkey

// sharedKeyReq is the shared key request handler.
// It executes the AuthCallback function to allow or deny the request to the client.
// The shared key equals to signatureECDSA(hash(processId)).
func (csp *BlindCSP) sharedKeyReq(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	req := &types.Message{}
	if err := req.Unmarshal(msg.Data); err != nil {
		return err
	}
	pid, err := hex.DecodeString(trimHex(ctx.URLParam("processId")))
	if err != nil {
		return fmt.Errorf("cannot decode processId: %w", err)
	}
	if len(pid) != processIDSize {
		return fmt.Errorf("wrong process id: %x", pid)
	}
	// Auth Step
	step, err := strconv.Atoi(ctx.URLParam("step"))
	if err != nil {
		// For backwards compatibility
		step = 0
	}

	var resp types.Message
	var authResp handlers.AuthResponse
	if authResp = csp.AuthCallback(ctx.Request, req, pid, types.SignatureTypeSharedKey, step); authResp.Success {
		if authResp.AuthToken == nil {
			resp.SharedKey, err = csp.SharedKey(pid)
			if err != nil {
				return err
			}
		}
	} else {
		return fmt.Errorf("unauthorized")
	}
	resp.Response = authResp.Response
	resp.AuthToken = authResp.AuthToken
	return ctx.Send(resp.Marshal(), bearerstdapi.HTTPstatusCodeOK)
}

func (csp *BlindCSP) info(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	if csp.InfoCallback == nil {
		return ctx.Send(nil, bearerstdapi.HTTPstatusCodeOK)
	}
	resp := csp.InfoCallback()
	if resp == nil {
		return ctx.Send(nil, bearerstdapi.HTTPstatusCodeOK)
	}
	return ctx.Send(resp.Marshal(), bearerstdapi.HTTPstatusCodeOK)
}

// https://server/v1/auth/ping

// ping is a simple health check handler.
func (csp *BlindCSP) ping(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	resp := &types.Message{Response: []string{"Ok"}}
	return ctx.Send(resp.Marshal(), bearerstdapi.HTTPstatusCodeOK)
}

func trimHex(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}
