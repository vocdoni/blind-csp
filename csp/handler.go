package csp

import (
	"fmt"

	"github.com/arnaucube/go-blindsecp256k1"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/bearerstdapi"
)

// SignatureTypeBlind is a secp256k1 blind signature
const SignatureTypeBlind = "blind"

// SignatureTypeEthereum is the standard secp256k1 signature used in Ethereum
const SignatureTypeEthereum = "ecdsa"

func (csp *BlindCSP) registerHandlers() error {
	if err := csp.api.RegisterMethod(
		"/processes/{processId}/{signType}/auth",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.signatureReq,
	); err != nil {
		return err
	}
	return csp.api.RegisterMethod(
		"/processes/{processId}/{signType}/sign",
		"POST",
		bearerstdapi.MethodAccessTypePublic,
		csp.signature,
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

	resp := Message{}
	var ok bool
	if ok, resp.Response = csp.AuthCallback(ctx.Request, req); ok {
		switch ctx.URLParam("signType") {
		case SignatureTypeBlind:
			r := csp.NewBlindRequestKey()
			resp.Token = r.Bytes()
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

	resp := Message{}
	switch ctx.URLParam("signType") {
	case SignatureTypeBlind:
		r, err := blindsecp256k1.NewPointFromBytes(req.Token)
		if err != nil {
			return err
		}
		resp.Signature, err = csp.SignBlind(r, req.Payload)
		if err != nil {
			return err
		}
	case SignatureTypeEthereum:
		var err error
		resp.Signature, err = csp.SignECDSA(req.Token, req.Payload)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid signature type")
	}
	return ctx.Send(resp.Marshal())
}
