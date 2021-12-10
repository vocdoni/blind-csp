package csp

import (
	"encoding/hex"
	"fmt"

	"github.com/arnaucube/go-blindsecp256k1"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/bearerstdapi"
)

// SignatureTypeBlind is a secp256k1 blind signature
const SignatureTypeBlind = "blind"

// SignatureTypeEthereum is the standard secp256k1 signature used in Ethereum
const SignatureTypeEthereum = "ecdsa"

// SignatureTypeSharedKey identifier the shared key (common for all users on the same processId)
const SignatureTypeSharedKey = "sharedkey"

const processIDSize = 32

func (csp *BlindCSP) registerHandlers() error {
	if err := csp.api.RegisterMethod(
		"/processes/{processId}/{signType}/auth",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.signatureReq,
	); err != nil {
		return err
	}

	if err := csp.api.RegisterMethod(
		"/processes/{processId}/{signType}/sign",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.signature,
	); err != nil {
		return err
	}

	if err := csp.api.RegisterMethod(
		"/processes/{processId}/sharedkey",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.sharedKeyReq,
	); err != nil {
		return err
	}

	return csp.api.RegisterMethod(
		"/health",
		"GET",
		bearerstdapi.MethodAccessTypePublic,
		csp.health,
	)
}

// https://server/v1/auth/processes/<processId>/<signType>/auth

// signatureReq is the signature request handler.
// It executes the AuthCallback function to allow or deny the request to the client.
func (csp *BlindCSP) signatureReq(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	req := &Message{}
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
	resp := Message{}
	var ok bool
	signType := ctx.URLParam("signType")
	if ok, resp.Response = csp.AuthCallback(ctx.Request, req, pid, signType); ok {
		switch signType {
		case SignatureTypeBlind:
			resp.Token = csp.NewBlindRequestKey().Bytes()
		case SignatureTypeEthereum:
			resp.Token = csp.NewRequestKey()
		default:
			return fmt.Errorf("invalid signature type")
		}
	} else {
		return fmt.Errorf("unauthorized")
	}
	return ctx.Send(resp.Marshal())
}

// https://server/v1/auth/processes/<processId>/<signType>/sign

// signature is the performing signature handler.
// If the token is valid and exist in cache, will perform a signature over the Hash
func (csp *BlindCSP) signature(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	req := &Message{}
	if err := req.Unmarshal(msg.Data); err != nil {
		return err
	}
	if req.Token == nil {
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

	resp := Message{}
	switch ctx.URLParam("signType") {
	case SignatureTypeBlind:
		r, err := blindsecp256k1.NewPointFromBytes(req.Token)
		if err != nil {
			return err
		}
		resp.Signature, err = csp.SignBlind(r, req.Payload, pid)
		if err != nil {
			return err
		}
	case SignatureTypeEthereum:
		var err error
		resp.Signature, err = csp.SignECDSA(req.Token, req.Payload, pid)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid signature type")
	}
	return ctx.Send(resp.Marshal())
}

// https://server/v1/auth/processes/<processId>/sharedkey

// sharedKeyReq is the shared key request handler.
// It executes the AuthCallback function to allow or deny the request to the client.
// The shared key equals to signatureECDSA(hash(processId)).
func (csp *BlindCSP) sharedKeyReq(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	req := &Message{}
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
	resp := Message{}
	var ok bool
	if ok, resp.Response = csp.AuthCallback(ctx.Request, req, pid, SignatureTypeSharedKey); ok {
		resp.SharedKey, err = csp.SharedKey(pid)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unauthorized")
	}
	return ctx.Send(resp.Marshal())
}

// https://server/v1/auth/health

// health is a simple health check handler.
func (csp *BlindCSP) health(msg *bearerstdapi.BearerStandardAPIdata,
	ctx *httprouter.HTTPContext) error {
	resp := &Message{Response: "Ok."}
	return ctx.Send(resp.Marshal())
}

func trimHex(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}
