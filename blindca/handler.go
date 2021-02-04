package blindca

import (
	"fmt"

	"github.com/arnaucube/go-blindsecp256k1"
	"github.com/vocdoni/multirpc/router"
	"github.com/vocdoni/multirpc/transports/mhttp"
	"go.vocdoni.io/dvote/log"
)

// SignatureTypeBlind is a secp256k1 blind signature
const SignatureTypeBlind = "ECDSA_BLIND"

// SignatureTypeEthereum is the standard secp256k1 signature used in Ethereum
const SignatureTypeEthereum = "ECDSA"

// SignatureReq is the signature request handler.
// It executes the AuthCallback function to allow or deny the request to the client.
func (ca *BlindCA) SignatureReq(rr router.RouterRequest) {
	msg := &BlindCA{}
	req := rr.Message.(*BlindCA)
	httpctx, ok := rr.MessageContext.(*mhttp.HttpContext)
	if !ok {
		log.Fatal("got an invalid router request which is not HTTP")
	}
	if ca.AuthCallback == nil {
		log.Fatal("no auth callback defined")
	}
	if ca.AuthCallback(httpctx.Request, rr.Message.(*BlindCA)) {
		msg.OK = true
		switch req.SignatureType {
		case SignatureTypeBlind:
			r := ca.NewBlindRequestKey()
			msg.Token = r.Bytes()
		case SignatureTypeEthereum:
			msg.Token = ca.NewRequestKey()
		default:
			msg.SetError(fmt.Sprintf("invalid signature type %s", msg.SignatureType))
		}
	} else {
		msg.SetError("unauthorized")
	}
	if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
		log.Warn(err)
	}
}

// Signature is the performing signature handler.
// If the token is valid and exist in cache, will perform a signature over the Hash
func (ca *BlindCA) Signature(rr router.RouterRequest) {
	var err error
	msg := &BlindCA{}
	req := rr.Message.(*BlindCA)
	if req.Token == nil {
		msg.SetError("token is empty")
		if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
			log.Warn(err)
		}
		return
	}
	switch req.SignatureType {
	case SignatureTypeBlind:
		if len(req.MessageHash) == 0 {
			msg.SetError("messageHash is empty")
			if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
				log.Warn(err)
			}
			return
		}
		r, err := blindsecp256k1.NewPointFromBytes(req.Token)
		if err != nil {
			msg.SetError(err.Error())
			if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
				log.Warn(err)
			}
			return
		}

		msg.CAsignature, err = ca.SignBlind(r, req.MessageHash)
		if err != nil {
			msg.SetError(err.Error())
			if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
				log.Warn(err)
			}
			return
		}
	case SignatureTypeEthereum:
		if len(req.Message) == 0 {
			msg.SetError("message is empty")
			if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
				log.Warn(err)
			}
			return
		}
		msg.CAsignature, err = ca.SignECDSA(req.Token, req.Message)
		if err != nil {
			msg.SetError(err.Error())
			if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
				log.Warn(err)
			}
			return
		}
	}
	msg.OK = true
	if err := rr.Send(router.BuildReply(msg, rr)); err != nil {
		log.Warn(err)
	}
}
